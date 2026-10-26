# Интерфейс сканирования: граница текущего API

## Purpose
Зафиксировать fixture/live границу и source-реализованный интерфейс bounded public Docker Hub image scan отдельно от серверной admission/coverage authority. Полное тело основано на live DIP-DOC-2 v7; unrelated audit, design, landing, accessibility и evidence требования сохранены, а устаревшие Alpine-only/future/cancellation формулировки заменены точным профильно-ограниченным контрактом. Source support и датированные single-target native proofs не означают blanket public-image/OS/ecosystem/production acceptance и не закрывают DIP-TASK-2/9.

Public `public-hub-amd64-v1` — отдельная composition; default/legacy guards не снимаются. Для public действуют численные bounds DIP-DOC-1, 11 ecosystems и отдельный Debian TEMP partition. `checked` не означает безопасно. LLM docs/implementation не оцениваются этой редакцией.

Amendment H7v2 от DIP-TASK-9 поверх DOC2v8 по новому запросу владельца на progress bar. Сохраняет все29 прежних requirements и unrelated audit/design/landing/cancellation/coverage. Native percent остаётся null: новое представление не создаёт процент/ETA или новый backend wire. Owner GET source теперь предоставляет durable-outcomes-v1 metadata по отдельному DOC1 amendment: native percent остаётся неизвестным; UI integration/source review/deployment ещё не означают native PASS. TARGET, не deployed acceptance; APPLY HOLD до coordinator review фактической реализации.

## Requirements

### Requirement: Отсутствующие реальные возможности
Интерфейс SHALL не выдавать недоступные браузеру операции за работающие и SHALL не выдавать демонстрационные данные за результаты реального скана.

#### Scenario: Внутренний API без browser ingress
- GIVEN API доступен только внутри Compose и нет авторизованного browser ingress
- WHEN пользователь открывает интерфейс сканирования
- THEN реальные действия недоступны с объяснением, а данные фикстур явно обозначены как демонстрационные.

### Requirement: Квитанция запуска не подтверждает digest
Интерфейс SHALL трактовать ответ POST 202 `{scanId,statusUrl,eventsUrl}` только как квитанцию задания и SHALL не выводить закреплённый digest/platform из изменяемого tag.

#### Scenario: Цель ещё не подтверждена
- GIVEN POST ответил 202, а авторизованный GET status не предоставляет закреплённые digest/platform
- WHEN показывается деталь задания
- THEN интерфейс показывает ожидание подтверждения цели, не изображая tag проверенным digest.

### Requirement: Доказательная запись источника и кандидата [P1]
Аудит SHALL до установки или копирования кода и стилей содержать отдельную запись для каждого рассмотренного источника RareUI и Canvas UI и каждого действительно идентифицированного кандидата: первичный URL источника и конкретного компонента (если установлен), подтверждённое имя (если установлено), дату и результат доступа, версию либо дату изученного материала, ссылки на первичные свидетельства, статусы проверок «проверено»/«не проверено», итог `pass`/`fail` и причины. Общая страница источника SHALL не считаться доказательством свойств отдельного компонента.

#### Scenario: Компонент установлен по первичному источнику
- GIVEN первичный источник позволил идентифицировать конкретный компонент
- WHEN оформляется аудит до его подключения
- THEN отдельная запись содержит его подтверждённые имя и URL, дату и результат доступа, свидетельства, неизвестные пункты и мотивированный `pass` либо `fail`.

#### Scenario: Источник недоступен
- GIVEN первичный источник, включая RareUI, недоступен и имя компонента нельзя подтвердить
- WHEN оформляется аудит обоих источников
- THEN запись источника содержит исходный URL, дату и ошибку доступа, неизвестные лицензию и атрибуцию, `fail` и решение оставить HTML/shadcn; имя кандидата не выдумывается.

### Requirement: Подтверждение лицензии и атрибуции [P1]
Аудит SHALL присваивать кандидату `fail`, если первичный источник недоступен или условия лицензии, права использования либо атрибуции не подтверждены применительно к нему. Для `pass` аудит SHALL фиксировать первичное свидетельство условий и требуемые способ и место размещения атрибуции.

#### Scenario: Условия неизвестны
- GIVEN лицензия или атрибуция конкретного кандидата не проверяется по первичному свидетельству
- WHEN принимается решение о допуске
- THEN неизвестное обозначено «не проверено», кандидат получает `fail` и не копируется, не устанавливается и не используется; условия не угадываются.

### Requirement: Совместимость, безопасность и дизайн-язык [P1]
Аудит SHALL оценивать совместимость с React 19 и Tailwind CSS 4, сторонние и peer-зависимости и их безопасность, влияние глобальных CSS/reset на существующие UI-компоненты, соответствие токенам цвета, типографике, радиусам и поведению фокуса. Отсутствие доказательства обязательного пункта SHALL означать «не проверено» и `fail`; аудит SHALL отделять статическую оценку от проверки в работающем приложении.

#### Scenario: Конфликт или недостаточное свидетельство
- GIVEN кандидат требует конфликтующую зависимость, меняет глобальные стили либо соответствие дизайн-языку не подтверждено
- WHEN оценивается его совместимость
- THEN запись указывает конфликт или «не проверено» и `fail`, а в рамках аудита манифест, lockfile, стили и код продукта не меняются.

### Requirement: Проверяемая доступность и HTML fallback [P1]
Аудит SHALL оценивать клавиатуру, видимый фокус, screen reader и семантику, контраст, `prefers-reduced-motion` и сохранение результатов, ошибок, coverage, статусов и действий в обычном HTML/shadcn без canvas-эффекта. Экспериментальный `html-in-canvas` SHALL рассматриваться только как необязательный декор; без наблюдаемого свидетельства доступности и fallback аудит SHALL отмечать «не проверено» и `fail`, не утверждая, что действующий интерфейс уже проверен.

#### Scenario: Эффект недоступен или ограничено движение
- GIVEN canvas-эффект не поддерживается либо запрошен reduced-motion
- WHEN оценивается кандидат Canvas UI
- THEN отчёт фиксирует требование оставить P0-данные и управление в HTML/shadcn и статус фактической проверки; без наблюдаемого свидетельства кандидат получает `fail`, а реализация fallback не объявляется выполненной.

#### Scenario: Декор скрывает содержимое
- GIVEN свидетельства показывают потерю необходимого контента, действия или фокуса на mobile, клавиатуре либо для screen reader
- WHEN принимается решение о кандидате
- THEN записаны конкретная причина `fail` и выбор не делать декор условием доступности P0; аудит не утверждает, что экран уже исправлен.

### Requirement: Воспроизводимая оценка JavaScript и mobile [P1]
Аудит SHALL для каждого кандидата фиксировать метод, среду и наблюдаемый результат оценки JS-стоимости и поведения на узком мобильном экране либо «не проверено», ограничение метода и `fail`; не сделанные измерения SHALL не публиковаться как факты.

#### Scenario: Замер без исполнения недоступен
- GIVEN надёжный замер JS/mobile без установки или исполнения кода провести нельзя
- WHEN составляется документальный аудит
- THEN указаны ограничение и «не проверено», итог `fail`, без вымышленных чисел и без изменений манифеста, lockfile, src или backend.

### Requirement: Значение допуска и безопасный отказ [P1]
Аудит SHALL ставить `pass` только при первичных свидетельствах лицензии и атрибуции и подтверждении всех обязательных проверок совместимости, безопасности, доступности, дизайн-языка и JS/mobile; любое неизвестное SHALL означать `fail`. Для каждого `fail` аудит SHALL фиксировать решение оставить обычный HTML/shadcn. `pass` SHALL означать только возможность отдельного будущего решения об интеграции, а не установленный компонент, production readiness или проведённый UI e2e-тест.

#### Scenario: Все рассмотренные кандидаты отклонены
- GIVEN рассмотренные кандидаты получили `fail` либо источник недоступен
- WHEN оформляется итоговое решение
- THEN отчёт рекомендует HTML/shadcn без дополнительного декора и не ставит аудит условием проектирования P0, не объявляя визуальный UI реализованным.

#### Scenario: Кандидат документально допущен
- GIVEN для конкретного кандидата получены подтверждения всех обязательных условий
- WHEN в аудите фиксируется `pass`
- THEN приведены свидетельства и способ атрибуции, а установка и проверка работающего интерфейса остаются отдельной работой.

### Requirement: Проектная композиция evidence-first интерфейса [P1]
После реализации редизайна интерфейс SHALL сохранять цель, статус, этап, coverage, ошибки и доступные действия в семантическом HTML без зависимости от декоративных эффектов или закрытой панели фильтра; Card и текстовый Badge допускаются как компоненты оформления, а Sheet — только для мобильного фильтра находок в детали.

#### Scenario: Деталь на мобильном экране
- GIVEN пользователь открыл деталь на экране 320 или 375px и закрыл фильтр находок
- WHEN он просматривает состояние скана и покрытие
- THEN цель, ошибки, coverage и находки доступны вне фильтра, а фокус возвращается к вызвавшему его элементу без горизонтального скрытия данных.

### Requirement: Правдивое представление покрытия и списка [P1]
После реализации редизайна интерфейс SHALL различать состояние скана `partial`, исходы checks `failed|unsupported|not_authorized|skipped|checked`, неизвестный процент прогресса, отсутствие API списка, отсутствие результатов и пустую текущую страницу фильтра, не изображая ни одно из них доказательством безопасности.

#### Scenario: Недоступный список и неполная деталь
- GIVEN у браузера нет авторизованного list API, а доступный демонстрационный scan содержит `partial`, `failed` и `percent=null`
- WHEN пользователь переходит между списком и деталью
- THEN список помечен «недоступен», демо обозначено как фикстура, detail текстом различает неполный scan и неудавшийся check, а неизвестный процент не превращается в ноль или живой прогресс.

#### Scenario: Фильтр текущей страницы не нашёл записей
- GIVEN серверная страница содержит findings, но выбранный локальный фильтр не нашёл совпадений
- WHEN отображается результат фильтра
- THEN указан охват только текущей страницы, доступен сброс фильтра, coverage остаётся видимым и «0 CVE» для всего отчёта не утверждается.

### Requirement: Проверяемое происхождение выбранного UI [P1]
Перед копированием или распространением выбранного исходника интерфейса проект SHALL фиксировать первичный URL, точный registry JSON либо commit и hash, условия notice/атрибуции и transitive зависимости; дизайн-одобрение SHALL не трактоваться как разрешение правообладателя, подтверждённая совместимость или готовность UI.

#### Scenario: Дизайн одобрен, но артефакт не закреплён
- GIVEN одобрена композиция shadcn/ui Radix Card/Badge/Sheet по датированному снимку документации, но нет hash конкретного исходника и проверки runtime
- WHEN планируется интеграция компонента
- THEN копирование откладывается до идентификации исходника, проверки условий использования и испытаний React 19/Tailwind 4, доступности и стоимости; исторический `fail` RareUI/Canvas не переименовывается в `pass`.

### Requirement: Демонстрационный landing на корневом маршруте
Маршрут `/` SHALL показывать демонстрационный landing с объяснением исследования OCI-образа и явно отличать иллюстрацию от результатов сканирования.

#### Scenario: Посещение главной страницы
- GIVEN пользователь открывает `/`
- WHEN загружается главная страница
- THEN доступен заголовок о безопасности образа, промо-иллюстрация подписана как не являющаяся результатом сканирования, текст предупреждает о вымышленных данных демо, а доступность настоящего запуска определяется авторизацией и подтверждёнными серверными capabilities.

### Requirement: Переходы из landing в сканы
Landing SHALL предоставлять отдельные ссылки на `/demo/scans` с вымышленными данными и `/scans` с авторизованными реальными данными либо честной причиной недоступности.

#### Scenario: Выбор демо и раздела сканов
- GIVEN пользователь находится на `/`
- WHEN он выбирает «Смотреть демо» либо «Раздел сканов»
- THEN первая ссылка ведёт на `/demo/scans` со списком фикстур, а вторая — на `/scans`, где авторизованный list API показывает только реальные ответы текущего субъекта; без ingress, прав или GET списка показывается причина недоступности, а не фиктивный live-результат.

### Requirement: Декоративное движение и доступное содержимое landing
Landing SHALL сохранять смысловой текст, этапы иллюстрации и навигацию в HTML независимо от декоративной анимации, скрывать чисто декоративные элементы от вспомогательных технологий и учитывать `prefers-reduced-motion`.

#### Scenario: Ограничение движения
- GIVEN у пользователя включён `prefers-reduced-motion: reduce`
- WHEN он открывает landing
- THEN начальное появление Motion не требует анимации, бесконечная бегущая строка и вращающийся декор не анимируются, а заголовок, текст, ссылки и список этапов остаются доступны в HTML.

#### Scenario: Декор не подменяет содержание
- GIVEN иллюстративный фон, орбиты, повторяющийся тикер и пиктограммы не озвучиваются
- WHEN пользователь читает страницу с помощью вспомогательных технологий
- THEN видимые смысловые заголовки, ссылки и список этапов остаются в семантическом HTML, а декоративные элементы исключены из дерева доступности.

### Requirement: Сохранение границы fixture и live при входе с landing
Переход с landing SHALL сохранять различие между локальными фикстурами демо и авторизованными реальными данными и действиями с их фактическими ограничениями.

#### Scenario: Два режима после перехода
- GIVEN пользователь переходит с `/` на `/demo/scans` или `/scans`
- WHEN загружается выбранный раздел
- THEN демо явно помечает записи как фикстуры и не выдаёт их за GET status или live-поток; реальный раздел показывает только разрешённые контрактом данные и действия, а при отсутствии защищённого доступа объясняет ограничение без подстановки демо или обещания запуска, отмены и SSE.

### Requirement: Вкладки исследования образа на landing
Landing SHALL показывать в секции «Исследуй глубже» переключаемые семантические вкладки «Образ», «Secrets» и «Покрытие» как вымышленные примеры концепции, а не результаты работающего API.

#### Scenario: Содержание и маркировка вкладок
- GIVEN пользователь открывает `/`
- WHEN он читает секцию «Исследуй глубже» и выбирает одну из трёх вкладок
- THEN соответствующая панель доступна как `tabpanel` именованного `tablist`, примеры помечены как концепт и вымышленные, вкладка «Secrets» не выдаёт пример за выполненную проверку и указывает на зависимость реального запуска от авторизации и серверного допуска, а «Покрытие» не выдаёт схему за SBOM или скан.

#### Scenario: Переключение клавиатурой
- GIVEN фокус находится на выбранной вкладке «Образ» секции «Исследуй глубже»
- WHEN пользователь нажимает ArrowRight дважды
- THEN фокус и `aria-selected` последовательно переходят на «Secrets» и «Покрытие», а видимый `tabpanel` показывает содержимое выбранной вкладки.

### Requirement: Текущая подтверждённая граница discovery
Интерфейс SHALL отличать discovery candidate от авторизованной eligibility выбранного reference/check-set и от pinned checked результата. Исторический baseline 5e3645b (первая страница/Alpine-only) не SHALL выдаваться за текущую границу public composition; серверный поиск сам по себе не доказывает tag/platform/inventory.

#### Scenario: Найден nginx сейчас
- GIVEN Hub вернул nginx с scannable:false и public-hub-profile hint
- WHEN кандидат выбран либо введён manual canonical reference
- THEN свежая server eligibility предшествует подтверждённому запуску, POST повторяет guards/inspection; hint не авторизация и не blanket qualification, default/legacy deployment остаётся в собственной policy.

### Requirement: Bounded discovery следующего среза
Система SHALL показывать валидные уникальные candidates загруженных страниц в source policy: page size 12, maxPages 5, maxCandidates 60, maxPageBytes 128000, maxBytes 640000, maxFetchMs 5000, maxTotalMs 25000, idle cursor 300000 ms, maxActivePerProcess 8, maxActivePerSubject 2, maxRequestsPerSubject 30/60000 ms, maxSessions/maxRateEntries 1024. Лимиты process-local, не cluster-global; browser generation допускает один актуальный запрос, invalidated late response не изменяет UI.

#### Scenario: Продолжение и исчерпание бюджета
- GIVEN первая страница содержит continuation и остаётся бюджет
- WHEN пользователь загружает следующую страницу
- THEN уникальные canonical references добавляются без скрытого slice и повторов с сохранением выбора/фокуса; more-available, terminal, quota-exhausted различаются, исчерпание означает неполноту, не upstream total.

#### Scenario: Terminal, expiry и ошибка
- GIVEN continuation истёк/утерян при рестарте либо upstream malformed/недоступен
- WHEN запрошено продолжение
- THEN expired/failed безопасно отличимы от terminal и сохраняют уже загруженное; неизвестная стоимость failed upstream retires cursor, новый поиск не обходит прежний бюджет. Cached replay того же cursor не дублирует candidates; валидная пустая next page не стирает найденное.

### Requirement: Scoped cursor и фиксированный transport
Сервер SHALL использовать opaque/server-owned либо подписанный cursor, связанный с subject, normalized query, repository/tags mode, canonical repo для tags, page size, expiry и request generation, без принятия произвольного upstream next URL как destination.

#### Scenario: Подмена, цикл или истечение cursor
- GIVEN continuation относится к другому subject/query/mode/repo/generation, подменён, истёк либо повторяет страницу циклом
- WHEN запрошено продолжение
- THEN сервер безопасно отклоняет его до запрещённого egress, уже показанная выдача остаётся явно неполной и доступен новый поиск; автоматического бесконечного обхода нет.

### Requirement: Авторизация и безопасный discovery
Система SHALL проверять search authorization и ресурсные лимиты до Hub egress, валидировать query как данные фиксированных HTTPS endpoints и сохранять fail-closed TLS/DNS/IP/redirect/realm контроль без произвольного egress или Docker socket; read-discovery не предоставляет `scan:create`.

#### Scenario: Unsafe query и bypass UI
- GIVEN query содержит URL/userinfo, localhost/metadata адрес, traversal `..`, `//`, control/newline, shell метасимволы, HTML либо превышает 64 символа
- WHEN browser API принимает запрос даже в обход UI
- THEN запрос отклонён безопасным `INVALID_IMAGE_SEARCH` до upstream, без shell/HTML исполнения; допустимые query передаются URL-encoded, недоверенные labels отображаются только текстом, invalid references отбрасываются.

#### Scenario: Auth, TLS и вредоносный upstream
- GIVEN нет разрешённой сессии, TLS certificate недоверен/истёк/не соответствует host, redirect/realm чужой либо DNS/IP private, mixed или rebound
- WHEN выполняется discovery
- THEN запрещённого обращения и отключения TLS verification нет; проверки выполняются на каждом разрешённом hop, credentials не передаются чужому host и не раскрываются, raw upstream body/tokens не показываются.

#### Scenario: Malformed payload и rate limit
- GIVEN upstream вернул timeout, 429, 5xx, неверный content-type/JSON или превысил bytes/time budget
- WHEN поиск завершается
- THEN показана безопасная ошибка или ограничение с повтором, не fabricated results или успешная пустота; cached данные имеют время получения либо неизвестную свежесть и явно не считаются актуальными.

### Requirement: Актуальный query и независимый saved выбор
Интерфейс SHALL ограждать results/loading/error/cursor поколением query, отдельно маркировать saved/fixture примеры и не выбирать кандидата автоматически; demo SHALL не выполнять discovery/scan запросы.

#### Scenario: Поздний ответ даже без abort
- GIVEN запрос A медленный, запрос B уже показал результат, а транспорт игнорирует abort
- WHEN возвращается A
- THEN A не изменяет results, selection, loading, error или cursor B; saved archival digest не подменяет выбранный live tag и не доказывает его текущие CVE.

#### Scenario: Очистка и смена намерения
- GIVEN идёт live поиск и выбраны target/checks
- WHEN query очищен или недопустим либо пользователь явно меняет target/checks
- THEN недопустимый query не отправляется, старая выдача и cursor не называются актуальными, сохранённая цель либо явно отделена, либо сброшена; смена target/checks сбрасывает согласие и не переиспользует idempotency key другого намерения, безопасный повтор того же намерения сохраняет прежний key.

### Requirement: Eligibility отдельно от found
Интерфейс SHALL отдельно показывать canonical repository/tag кандидата, подтверждённые сервером доступные checks и безопасную причину `unsupported` либо неизвестного допуска; `scannable` является только UI hint и не авторизацией.

#### Scenario: Неподдержанный или неизвестный кандидат
- GIVEN discovery вернул официальный или namespaced repository, но полная scan цепочка профиля не подтверждена
- WHEN пользователь видит кандидата либо подменяет `scannable=true` в POST
- THEN кандидат остаётся видимым, UI launch disabled с понятной причиной, сервер отказывает до нового enqueue независимо от hint; имя репозитория не считается доказательством OS/ecosystem, существования tag или платформы.

### Requirement: Будущий авторитетный image admission
Система SHALL принимать public image scan только через отдельную public composition для явного canonical registry-1.docker.io/library/name:tag либо namespace/name:tag или @sha256:lowercase64, image/linux/amd64, с повторными auth/permission/origin/quota/readiness/DB guards и verified single child/config pin до enqueue. Manual reference не расширяет registry/platform/resources. Default и exact LOCAL profiles сохраняют свои admission boundaries.

#### Scenario: Tag drift и idempotent replay
- GIVEN tag изменился после поиска либо повторяется прежнее намерение
- WHEN отправляется scan
- THEN новое допустимое намерение закрепляет текущие verified bytes либо отказывает до enqueue; replay прежнего subject/key возвращает прежний scan до resolution/readiness, конфликт не создаёт job. 202 — receipt, server GET подтверждает ту же pinned identity без Alpine projection.

#### Scenario: Tag или платформа отсутствует
- GIVEN tag отсутствует, child linux/amd64 неоднозначен или config/hash/platform не совпадает
- WHEN inspection проверяет цель
- THEN нет fallback на иной tag/platform и нет нового 202; UI показывает безопасную причину и сохраняет независимый пользовательский выбор.

### Requirement: Будущие числовые scan bounds и registry-only изоляция
Система SHALL сохранять public-hub-resources-v1 из DIP-DOC-1: 64layers, compressed128/512MiB layer/total, delivered bodies544MiB, 320attempts/180s acquisition, expanded512/1024MiB, 100000entries/256MiB file, archive1152MiB/logical scratch2048MiB; metadata4MB/config1MB и inspection16MB/12attempts/30s. Public worker4GiB/no-swap/CPU1/PIDs128/tmpfs2304MiB; stage120s/attempt600s; stdout Secrets1000000B/SBOM2000000B/vuln8000000B, ≤1000 records; serialized archive/checkpoint ≤2000000B. Legacy ceilings не расширяются. Registry transport остаётся exact-host HTTPS/DNS/IP/realm/repository-pull с bounded redirects без direct fallback/socket.

#### Scenario: Compression bomb или unsafe layer
- GIVEN actual download/unpack/tar/resource/output bound превышен либо layer/media/identity недопустимы
- WHEN inspection/worker обрабатывает цель
- THEN безопасный admission отказ либо failed check/прерывание с owned cleanup не становится truncated checked/0; token не отправляется CDN, query/user flags не повышают caps. wireBytes — delivered response-body accounting без headers/CONNECT/TLS overhead, не физический wire.

### Requirement: Независимые coverage и freshness будущего scan
Отчёт SHALL отдельно показывать сохранённые OS/Node coverage details и per-check Secrets/SBOM/vuln/config с безопасными reasons, pinned target, историческими check/scanner/DB versions/timestamps; null/unknown не становятся checked/0. Public parser принимает только receipt-backed profile и закрытые apk/deb/rpm/npm/pypi/gem/gomod/cargo/maven/composer/nuget, а endpoint/repository сами не повышают legacy grammar. Public DB usability следует закреплённой cve-db-updated-at-14d-v2, не discovery time: >24h и overdue NextUpdate — warnings, age>14days — unusable; signature/hash/schema guards независимы.

#### Scenario: OS checked, Node неизвестен и CVE DB failed
- GIVEN public OS inventory проверен, npm не доказан либо DB/parser отказал
- WHEN report отображается
- THEN checked vuln не превращает Node unsupported/NODE_INVENTORY_UNKNOWN в checked/absent; DB_UNAVAILABLE означает failed vuln без count при сохранённых Secrets/SBOM. Local attestation не называется подписью Aqua; historical receipt не свидетельствует о сегодняшней freshness.

#### Scenario: Scratch, EOL и подтверждённый ноль
- GIVEN OS неизвестна, валидированный EOSL:true либо malformed/missing required packages, или конкретный checked dataset действительно пуст
- WHEN отображается coverage
- THEN OS_UNKNOWN/OS_EOL дают unsupported без count, invalid required inventory — failed; только checked empty dataset допускает ноль в его области, не безопасный образ. Filter-empty/page-empty не заменяют total; отсутствие npm inventory не доказывает отсутствия Node.

### Requirement: Однозначный future terminal reducer
Система SHALL без cancellation вычислять terminal по выбранным requested checks secret/sbom/vuln/config: completed только если каждый selected check checked; partial если checked хотя бы один, но не все; failed если ни одного. OS/Node являются coverage details vuln, не дополнительными selectable checks: unknown Node при checked vuln не даёт автоматический partial. Pустой checks input отвергается до enqueue; unrequested не считается выполненным. UI не пересчитывает server state по count или SSE close.

#### Scenario: All-unexecuted и secret-only
- GIVEN выбран только secret либо все selected checks failed/unsupported
- WHEN terminal snapshot получен
- THEN secret-only completed требует secret checked, остальные unrequested не становятся checked; отсутствие checked не даёт completed, failed имеет фактическую причину, не выдуманный NO_EXECUTED_CHECKS code.

#### Scenario: Unsupported requested область
- GIVEN secret checked, а selected vuln unsupported из-за OS_EOL
- WHEN формируется итог
- THEN scan partial и vuln limitation не скрыта как unrequested; checked vuln с OS checked/Node unknown остаётся отличимым случаем.

### Requirement: Cancellation, fence и scoped snapshot
Система SHALL при owner cancel queued/running scan публиковать только eligible durable completed checkpoints текущего исходного claim и атомарно фиксировать cancelled, отзыв token/outbox и один terminal event; итог остаётся cancelled при нуле, части и всех saved checks. Terminal completed, выигравший раньше cancel, неизменяем и даёт конфликт отмены. SSE — hint к authoritative owner GET, не источник результата/полномочий/100%.

#### Scenario: Cancel после первого check и completed-before-cancel
- GIVEN один check durable committed либо scan уже completed
- WHEN поступают cancel и поздняя worker запись
- THEN первый остаётся cancelled с сохранёнными findings/coverage и unknown отсутствующими siblings, второй сохраняет completed; missing/wrong/revoked/expired original token не пишет. Cancel не синтезирует partial/failed/check timeout или checked-zero для незавершённого.

#### Scenario: Reopen, clock fence и historical coverage
- GIVEN checkpoint committed до expiry, потом API/worker перезапущен либо lease_until равен/меньше clock
- WHEN owner отменяет либо старый worker пытается записать новый результат
- THEN expiry запрещает новые writes, но eligible ранее accepted snapshot текущего non-revoked claim сохраняется при cancel; retry/replacement отзывают его и не смешивают attempts. Исторические checkedAt/DB evaluation не обновляются временем cancel/reload, null coverage не становится skipped/checked.

#### Scenario: Смена субъекта и страницы отменённого отчёта
- GIVEN cancelled report имеет saved Secrets/SBOM/vuln/config subset и текущую сессию
- WHEN owner листает/reloads либо меняется subject
- THEN сохранённые datasets имеют прежние version/cursor/identity/count guards; requested missing остаётся null/unknown, missing report route 404 не проверенный ноль. Чужой cache/stream закрыт, reads авторизованы заново; нет запроса к отсутствующему dataset и нет fixture substitution.

### Requirement: Доступность и доказательная поэтапная приёмка
Приёмка SHALL отдельно фиксировать mocked, controlled integration и датированное live evidence, сохраняя keyboard/SR и управление на 320/375px; search/paging SHALL не закрывать DIP-TASK-9 или DIP-TASK-2 и не подтверждать общий public-image scan.

#### Scenario: Discovery срез
- GIVEN следующий discovery срез подготовлен
- WHEN проверяются paging duplicates, cursor endpoint/repo/subject substitution, expiry/cycle/quota, malformed/auth/unsafe input и stale response ignoring abort
- THEN controlled tests отделены от live smoke Alpine 3.16/nginx; unavailable smoke отмечен blocked, не pass, reference/disabled reason/error/повтор доступны на узком экране без потери фокуса, aria-live не озвучивает каждый элемент.

#### Scenario: Приёмка расширенного runnable scan
- GIVEN отдельный backend профиль готов к включению
- WHEN проверяется авторизованный browser→API→worker non-Alpine positive и negative admission, pinned image matrix и independent coverage/freshness
- THEN доказательства охватывают OS/Node/SBOM/secrets, auth/subject/egress/DB/bounds/cancel/lease и сохранение identity; Alpine-based non-library профиль, mocks, offline rootfs и search-only не заменяют non-Alpine приёмку. Исходные criteria partial CVE failed/secrets checked, findings pagination/filter distinction, SSE→GET без фиктивных 100%, cancel preserving findings и browser без Trivy/Docker остаются обязательными; до полной приёмки либо явного человеческого сужения scope задача остаётся незавершённой.

### Requirement: Честный public CVE и Debian TEMP UI partition
Интерфейс SHALL показывать public vulnerability findingCount как сумму identifierCounts.cve и identifierCounts.debianTemp всего сохранённого checked dataset до фильтров, не называть все vulnerabilities CVE. TEMP допустим только для public/deb и строгой grammar TEMP-seven-digits-uppercase-six-hex; legacy остаётся CVE-only. Public TEMP не получает выдуманный CVE/NVD/FIRST/БДУ link.

#### Scenario: Dataset partition и page filter
- GIVEN public Debian report содержит 236 CVE и 5 TEMP либо иной валидный фактический partition
- WHEN status/ordinary/report-v1/browser читают страницы и filters
- THEN общий count равен сумме partitions, server partition не заменён page/matched counts; на странице отдельно виден её partition. Missing/inconsistent counts, malformed namespace, duplicate IDs и raw extra fields отклоняются strict parsing, не становятся пустым checked report. Исторические 236/5 не hardcoded expectation будущего scan.

### Requirement: Доступный индикатор фактического прогресса
Интерфейс SHALL показывать согласованный индикатор выполнения в списке и детали по текущему авторизованному snapshot, оставляя его indeterminate при percent=null и неизвестном ETA, без вымышленных процентов, таймеров завершения и 100% от SSE close/reconnect.

#### Scenario: Выполнение с неизвестным total
- GIVEN текущий scan queued/running, native percent=null и сервер не даёт проверенную оценку времени
- WHEN показывается progress bar в списке или детали
- THEN видны фактическое состояние и пояснение «Точное оставшееся время неизвестно»; числовой процент, countdown и aria-valuenow отсутствуют, indeterminate индикатор имеет доступное имя и не скрывает findings/coverage/ошибки/действия.

#### Scenario: Терминальный snapshot и отмена
- GIVEN получен авторизованный completed/partial/failed/cancelled snapshot
- WHEN обновляется индикатор
- THEN отображается серверный итог без продолжающегося ожидания и без утверждения, что все checks checked при partial/failed/cancelled; cancelled subset и historical coverage сохраняются, native percent=null не становится fabricated100.

#### Scenario: Доступность и позднее событие
- GIVEN включён reduced-motion либо приходит поздний SSE hint после свежего snapshot/смены субъекта
- WHEN progress UI обновляется
- THEN движение заменяется статическим представлением, важный stage/terminal переход объявляется дозированно без потери фокуса; stale hint не регрессирует snapshot и не раскрывает другой scan.

### Requirement: Подтверждённый этап и оставшиеся выбранные проверки
Интерфейс SHALL показывать конкретный текущий этап, readiness и число оставшихся выбранных checks только в пределах подтверждённых авторизованных серверных данных; отсутствие projection означает unknown, а не вычисленное время или угаданный этап scanner.

#### Scenario: Projection отсутствует
- GIVEN доступны только scan state/percent=null и нет отдельного подтверждённого stage/selected-check projection
- WHEN пользователь хочет понять, сколько осталось
- THEN интерфейс показывает только известное queued/running/readiness состояние и явно неизвестные детали; elapsed time, число findings, страницы и четыре возможных checks не превращаются в процент, ETA или предположение о текущем check.

#### Scenario: Подтверждённый completed subset
- GIVEN авторизованные данные текущей попытки явно задают selected checks и фактически завершённый subset
- WHEN показывается «выполнено N из M» либо remaining checks
- THEN учитываются только эти selected checks и подтверждённый subset; unrequested/missing/failed не называются checked, количество checks не объявляется долей времени или доказательством безопасности. Projection проверяется по DOC1 owner-only metadata contract; это не промежуточная публикация findings и не разрешение result routes.

### Requirement: Live counters и polling независимо от SSE
Интерфейс SHALL читать owner GET status ограниченным polling пока scan активен, даже при подключённом SSE, и показывать durable-outcomes-v1 counters отдельно от неизвестного процента/ETA и от findings.

#### Scenario: Checkpoint без нового state event
- GIVEN scan running и очередной accepted checkpoint изменил progress без перехода scan state
- WHEN SSE остаётся подключённым, а очередной owner GET возвращает новую согласованную projection
- THEN list/detail показывают resolvedChecks из requestedChecks и отдельно checkedChecks, selected outcomes и оставшееся M-minus-resolved без определения текущей длительности или scanner substage; failed/unsupported не называются checked, null не становится0findings. Отсутствующий progress даёт unknown, не synthetic counters.

#### Scenario: Завершение, stale response и приватность
- GIVEN получен terminal snapshot либо изменились scan/session/owner
- WHEN polling/SSE callback завершается поздно
- THEN polling/stream прежнего scope прекращаются, stale данные не восстанавливают counters/findings; terminal state берётся из GET, failed/cancelled не превращаются в100 или completed от всех resolved. Running result/perCheck/findings остаются недоступными по прежним publication guards; counters не открывают чужой report.

## Non-goals
- Эта полная редакция согласует source-реализованные bounded paging/public admission/coverage/cancellation, а не весь P0. Source — DIP-TASK-9; реальные MCP full-body validation/propose/apply receipts фиксируются отдельно в reconciliation manifest, не предполагаются по наличию файла. Stale base-v1 full-P0 дельта не заменяет текущий resulting body; приёмка и статусы задач не меняются.
- Landing и fixture-preview не доказывают browser ingress, GET списка, отмену, CVE/SBOM или live SSE; фактические live возможности проверяются отдельно по авторизации и контракту, а их отсутствие не утверждается безусловно для всего стенда.
- Discovery не снимает legacy Alpine/exact guards. Public composition отдельно допускает bounded Hub targets; Debian/Node native evidence 2026-10-18 имеет single-target scope, не universal qualification. DOC-1 задаёт backend safety/resource контракт, UI его не заменяет.
- «Любой найденный runnable» означает запрос registry image scan выбранного canonical repository/tag при серверном допуске, не выполнение workload/entrypoint и не универсальную поддержку OS/ecosystems/размеров/platforms. Private registries, произвольные URL, host/container scan, socket/host mounts, writable layers/volumes/traffic вне области.
- Аудит кандидатов не устанавливает библиотеки, не копирует код или стили, не меняет frontend/backend и не заменяет визуальную реализацию `DIP-TASK-12`.
- Контракт аудита не является доказательством лицензии, совместимости, измерения JS/mobile или доступности конкретного кандидата: такие факты требуют отдельных первичных свидетельств и наблюдаемых проверок.
- Дизайн-signoff DIP-TASK-19 подтверждает композицию, но не установленный shadcn Sheet, pinned upstream hash или работающий live UI.
- Проверка landing по fixture e2e и исходникам не подтверждает ручную screen-reader проверку, Safari/Firefox или production e2e.

## Датированная evidence attribution — 2026-10-21
Public prepare/migration/fresh upstream activation по авторскому handoff подтверждены отдельно от browser acceptance; scheduler не установлен/native-qualified, post-LLM refresh не выполнялся. Positive native Secrets packet охватывает четыре реальные scanner invocations с искусственными never-issued canaries и временный owner HTTP/SSE/storage harness; controlled cancel barriers и JSDOM не называются production browser E2E. Duplicate rows — производная harness mutation, не наблюдавшийся native duplicate output; positional IDs сохраняют первое исходное вхождение, не обещают стабильность при reorder. Node native receipt содержит 158 CVE (97 apk + 61 npm), 217 SBOM components, включая 200 npm; это scoped single-target история, не универсальная матрица ecosystems. Hashes/границы и оригинальные AC перечислены в `docs/public-spec-reconciliation-20261020.md`. Датированный HOLD/new token drift investigation не меняет permanent terminal reducer или UI contract и не подтверждает текущее live состояние; LLM/provider приёмка вне этого scope.
