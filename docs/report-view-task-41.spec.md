# DIP-TASK-41 / DIP-TASK-39 — Сохранённые отчёты и server-global report-v1

## Purpose
Полный локальный draft следующего тела DIP-DOC-10: server-global фильтры, сортировка и query-bound страницы сохранённых CVE/SBOM/Secrets. База — applied версия 3: c8b710c1-28a4-499b-8135-cdb667476be3 применена пользователем 2026-10-15 поверх версии 2; её laptop/v2-wire требования сохранены. На момент финализации Flownix недоступен: source41 delta для этого тела не создана и не применена. Локальная реализация проверена unit, настоящим HTTP/SQLite и browser integration на синтетическом сохранённом отчёте (docs/release-readiness-20261015.md); это не scanner/production deployment acceptance. Перед закрытием TASK41 требуется validate/propose/apply полного тела через MCP и фиксация narrow приёмки.

## Requirements

### Requirement: Фактическая граница отчёта
Интерфейс SHALL не трактовать наличие этой спецификации или synthetic fixture как доказательство выполненного сканирования, доступности scanner/API или безопасности образа.

#### Scenario: Проверка по synthetic fixture
- GIVEN интерфейс испытывается только с вымышленными локальными ответами
- WHEN оценивается готовность отчёта
- THEN fixture подтверждает только проверенные свойства UI, а серверные capabilities и покрытие требуют отдельных доказательств.

### Requirement: Независимые последовательные страницы
Интерфейс SHALL предоставлять самостоятельные действия «Назад» и «Далее» для CVE, Secrets и SBOM, используя только выданное API продолжение и ранее посещённые cursors своей категории.

#### Scenario: Переключение страницы CVE
- GIVEN загружены первые страницы трёх категорий и API выдал nextCursor CVE
- WHEN пользователь открывает следующую страницу CVE и затем возвращается назад
- THEN запрашиваются только соответствующие cursors CVE, а страницы Secrets и SBOM не меняются; смена видимости категории сохраняет независимое состояние.

### Requirement: Подтверждённый номер и диапазон
Интерфейс SHALL изменять номер и диапазон показанных строк только после подтверждения запрошенной страницы.

#### Scenario: Запрос ещё выполняется
- GIVEN показана первая подтверждённая страница
- WHEN пользователь открывает следующую страницу и ответ ещё не получен
- THEN прежние строки, номер и диапазон сохранены, загрузка явно указана, а действия этого pager отключены без дублирования запроса.

### Requirement: Ошибка перехода с сохранением данных
Интерфейс SHALL сохранять предыдущие подтверждённые строки при обычной ошибке перехода и предлагать повтор именно неудавшегося запроса.

#### Scenario: Следующая страница недоступна
- GIVEN первая страница подтверждена для текущего отчёта
- WHEN GET следующей страницы завершается ошибкой сети или безопасным временным отказом
- THEN ошибка явно отличена от успешного перехода, показан прежний подтверждённый диапазон, а retry не пропускает cursor и не объявляет пустой результат.

### Requirement: Сброс идентичности и доступа
Интерфейс SHALL очищать все видимые и сохранённые строки, активное подтверждение и cursor history при утрате доступа либо смене субъекта, поколения сессии, scan, закреплённой цели или доступной идентичности/метаданных отчёта, включая предоставленные checkedAt/count/scannerVersion. Это строгое очищение распространяется и на ранее сохранённый исторический снимок; fallback к его строкам в новом или утратившем доступ контексте недопустим.

Только при повторе ранее посещённого cursor в том же авторизованном контексте, с неизменными целью, доступными метаданными отчёта, ordered finding IDs, cursor и continuation, когда меняется лишь нормализованное содержимое строк, интерфейс SHALL отвергать входящий payload и сохранять ровно последний ранее подтверждённый снимок как явно исторический/устаревший, с неподтверждённой актуальностью повторного ответа. Его прежние строки, номер, диапазон и count относятся только к этому снимку, не подтверждают ответ отклонённого cursor и не смешиваются с ним; активное подтверждение и все cursor stacks сбрасываются, «Назад»/«Далее» отключены, а retry начинается с первого cursor. Эта узкая content-only граница не разрешает сохранение строк при смене доступа, контекста, цели или предоставленных метаданных отчёта.

#### Scenario: Смена субъекта во время GET
- GIVEN Alice открыла следующую страницу и ответ задержан
- WHEN интерфейс переходит к Bob или другому scan
- THEN все видимые и сохранённые строки Alice очищены, история начинается с первой страницы нового контекста, прежний запрос отменён, поздний ответ Alice не отображается и её строки не берутся из общего кэша страниц.

#### Scenario: Другая цель или версия ответа
- GIVEN статус подтверждает digest, platform и доступные checkedAt/count/scannerVersion
- WHEN ответ страницы не совпадает с этими данными либо меняет подтверждённую identity/итог между страницами
- THEN входящий payload не отображается, все прежние видимые и сохранённые строки, включая исторический снимок, активное подтверждение и cursor history очищены; восстановление начинается с первой страницы, без смешения отчётов.

#### Scenario: Потеря доступа
- GIVEN имеются подтверждённые строки текущего пользователя, в том числе ранее сохранённый исторический снимок
- WHEN GET сообщает об утрате сессии, разрешения или доступности scan
- THEN все видимые и сохранённые строки и cursor history очищены, pager отключён и требуется восстановление доступа, а не fallback к прежним данным.

#### Scenario: Content-only drift посещённой страницы в том же контексте
- GIVEN имеется последняя подтверждённая страница того же авторизованного субъекта, поколения сессии, scan и цели, а доступные метаданные отчёта, ordered finding IDs, cursor и continuation посещённой страницы неизменны
- WHEN «Назад» или повторный «Далее» получает для этого посещённого cursor ответ с изменением только нормализованного содержимого строк, например severity, fix или описания источника
- THEN отклонённый payload никогда не отображается; сохранён ровно последний ранее подтверждённый снимок с прежними строками, номером, диапазоном и count, явно относящимися к историческому/устаревшему снимку с неподтверждённой актуальностью ответа; активное подтверждение и все cursor stacks сброшены, навигация отключена, retry направлен к первому cursor.

#### Scenario: Обычная ошибка retry после content-only reset
- GIVEN после content-only drift показан явно исторический/устаревший последний подтверждённый снимок, cursor stacks сброшены и retry направлен к первому cursor
- WHEN retry завершается обычной сетевой или временной ошибкой без смены доступа, контекста, цели или метаданных отчёта
- THEN сохранены тот же исторический снимок и явное предупреждение о неподтверждённой актуальности, навигация остаётся отключённой, а следующий retry снова направлен к первому cursor.

#### Scenario: Успешная первая страница после content-only reset
- GIVEN показан исторический/устаревший снимок после content-only drift и retry направлен к первому cursor
- WHEN первая страница текущего авторизованного контекста успешно подтверждена
- THEN она заменяет исторический снимок как новая первая подтверждённая страница с новым baseline/history; прежняя stale-пометка снята, а навигация разрешена только по новым подтверждённым cursors.

### Requirement: Непротиворечивая последовательность
Интерфейс SHALL отвергать циклическое продолжение, повторяющиеся идентификаторы строк и несовместимый повтор посещённой страницы.

#### Scenario: API повторяет cursor или строки
- GIVEN первая страница подтверждена
- WHEN ответ следующей страницы повторяет её finding IDs либо даёт циклический cursor или пустую страницу с продолжением
- THEN переход не подтверждается, прежний диапазон не увеличивается и показана ошибка без бесконечной автозагрузки.

### Requirement: Отдельные достоверные итоги
Интерфейс SHALL подтверждать count категории только для выполненной проверки и различать checked zero, unknown, failed, unsupported, ожидание результата и отсутствие совпадений на текущей fixture-странице.

#### Scenario: CVE failed при успешном SBOM
- GIVEN CVE не выполнены, а SBOM успешно выдаёт инвентарь
- WHEN пользователь читает отчёт
- THEN число CVE неизвестно, число пакетов SBOM относится только к инвентарю и не объявляется количеством уязвимостей или доказательством безопасности.

#### Scenario: Checked zero и локальный фильтр
- GIVEN выполненная категория подтверждает count=0 либо fixture-фильтр скрывает имеющиеся строки текущей страницы
- WHEN показывается результат
- THEN только первое состояние называется нулём в проверенной области; второе называется отсутствием совпадений текущей страницы с доступным сбросом фильтра.

### Requirement: Компактные факты CVE
Интерфейс SHALL показывать CVE ID, severity, пакет, установленную и исправленную версии, известные расхождения и неизвестную согласованность источников без hover или обязательного раскрытия подробностей.

#### Scenario: Совместимое LOW при CRITICAL источника
- GIVEN headline содержит совместимое LOW, а отдельная оценка источника содержит CRITICAL
- WHEN строка CVE закрыта
- THEN виден текст о CRITICAL отдельного источника и расхождениях, а LOW не выдаётся за единственную авторитетную оценку.

### Requirement: Отдельные оценки и ограничения
Интерфейс SHALL раскрывать описание, источник и provenance, язык, исходные severity/fix/CVSS каждой оценки и ограничения предоставленных данных без выдуманного объединённого CVSS или пересчёта score.

#### Scenario: Две конфликтующие оценки
- GIVEN источники предоставили разные severity, fix и CVSS score
- WHEN пользователь раскрывает строку CVE
- THEN обе оценки читаются отдельно, вектор и score/state относятся к своему источнику, а missing/invalid/redacted/truncated/omitted сведения не подменяются выдуманными фактами.

### Requirement: Безопасные тексты и ссылки
Интерфейс SHALL сохранять существующие redaction/plaintext и canonical URL fences для advisory, не исполняя HTML/Markdown/URL источника и не отображая значения секретов.

#### Scenario: Просмотр advisory и калькулятора
- GIVEN нормализованный advisory содержит безопасный текст и допустимый CVE ID с валидным CVSS 3.1
- WHEN пользователь раскрывает подробности
- THEN текст экранирован, ссылки строятся только на канонические CVE.org/NVD и фиксированный FIRST без автозаполнения; внешние переходы не получают opener/referrer, а существование записи не объявляется проверенным.

### Requirement: Доступное чтение без вымышленного доступа
Интерфейс SHALL сохранять клавиатурное раскрытие, видимый фокус и читаемые данные на 320/375px и desktop, не предлагая totalPages, произвольную страницу, автозагрузку всего отчёта или глобальную сортировку/фильтрацию по одной загруженной странице. В legacy/no-view режиме глобальные controls не предлагаются; в opt-in report-v1 они допустимы только как серверные операции над полным сохранённым bounded отчётом, а не как локальная имитация.

#### Scenario: Мобильная клавиатура
- GIVEN открыт мобильный отчёт и включён reduced-motion
- WHEN пользователь раскрывает CVE, использует pager и закрывает мобильный выбор категории
- THEN данные доступны в HTML без горизонтального скрытия, фокус управления видим и после закрытия выбора возвращается к trigger; номер описывает посещённую страницу, а не выдуманное общее число страниц.

### Requirement: Независимость ИИ-источников
Интерфейс SHALL сохранять существующие проверяемые ссылки ИИ-сводки на findings других страниц и скрытых категорий независимо от текущего pager.

#### Scenario: Цитата последующей страницы Secrets
- GIVEN существующий механизм сводки подтвердил source citation другой страницы текущего авторизованного отчёта
- WHEN пользователь читает сводку при скрытой категории Secrets
- THEN доступна проверенная исходная находка; pager не подменяет report context и не вызывает генерацию модели автоматически.

### Requirement: Навигация только по доступным страницам
Интерфейс SHALL показывать компактные явно подписанные действия cursor-навигации сверху и снизу подтверждённого непустого набора с доступным продолжением либо ранее посещённой страницей, не отображая бессмысленные кнопки для unsupported, failed, отсутствующего результата, ожидания или checked zero без страниц. Оба набора действий используют одно подтверждение и один запрос; статус объявляется один раз.

#### Scenario: Реальные страницы CVE
- GIVEN проверенная непустая страница CVE предоставляет nextCursor
- WHEN пользователь читает начало или конец списка
- THEN доступен подписанный pager CVE с обеих сторон, фактический номер и диапазон не дублируются в live announcements; нет выдуманного totalPages, а global controls доступны только через report-v1, не через legacy/no-view.

#### Scenario: Нет доступной пагинации
- GIVEN CVE unsupported, failed, ещё выполняются, отсутствуют либо подтверждают ноль строк без continuation
- WHEN показан исход проверки
- THEN причина или ожидание остаётся видимой, но не отображается форма disabled Назад/Далее; неподдерживаемая проверка не называется checked zero.

### Requirement: Полноширинные находки на ноутбуке
Интерфейс SHALL размещать компактное покрытие перед полноширинными результатами с читаемыми шрифтами, видимым фокусом и управляющими элементами высотой не менее 44px на 320/1024/1280/1440px, сохраняя видимые исходы и причины проверок.

#### Scenario: Компоновка отчёта
- GIVEN открыт отчёт на мобильном устройстве или ноутбуке
- WHEN пользователь читает покрытие и CVE
- THEN находки занимают полную доступную ширину ниже покрытия, а текст и кнопки не скрываются горизонтальным переполнением; декоративная scene не выдаётся за ход проверки.

### Requirement: Закрытые метаданные CVE v2
Интерфейс SHALL принимать явный resultContractVersion 2 только с полным закрытым evidence: неизменённой db identity envelopeVersion 1, точным dbPolicy receipt ровно из пяти полей версии 2 для cve-db-updated-at-14d-v2, числовыми workerCheckedAt/evaluatedAt, исходным ISO checkedAt и точно производным usableUntil. Проверка согласованности использует сохранённые clocks, точные UTC наносекунды, календарь, порядок времён, допуск будущего 300 секунд, интервал публикации до 7 дней, включительный предел UpdatedAt + 14 дней и фиксированные упорядоченные warnings; это не криптографическая проверка подписи браузером.

#### Scenario: Исторический reload успешного или unsupported v2
- GIVEN сохранены согласованные successful или unsupported CVE v2 и их исходные timestamps
- WHEN владелец повторно открывает отчёт через год
- THEN envelope/timestamps/receipt не переписываются, допустимость проверяется на сохранённые worker/evaluated clocks, а не на текущую дату; unsupported не получает вымышленный count.

#### Scenario: Неполный либо несовместимый receipt
- GIVEN ответ содержит v2-marker или часть новых metadata fields
- WHEN версия неизвестна, поле снято, добавлено лишнее поле receipt, нарушен календарь/границы либо timestamps/status/warnings/expiry не согласованы
- THEN ответ отвергается без stripping или legacy fallback; failed outcome не получает вымышленные usable evidence, а прежняя legacy wire shape остаётся неизменной.

#### Scenario: Несогласованные status и страницы
- GIVEN status/perCheck подтверждают versioned CVE evidence
- WHEN redundant result или полученная страница предоставляют другие или отсутствующие metadata
- THEN ответ не публикуется; page metadata drift очищает прежние и исторические строки с first-cursor recovery, не попадая в content-only retention exception.

### Requirement: Правдивые сохранённые предупреждения базы
Интерфейс SHALL показывать возраст базы и policy warnings на сохранённый момент оценки без обязательного раскрытия, отдельно отличая UpdatedAt, DownloadedAt, NextUpdate как ожидаемую публикацию и usableUntil как включительный предел политики; историческая допустимость не объявляется текущей готовностью или гарантией безопасности.

#### Scenario: База старше суток и публикация просрочена
- GIVEN receipt v2 содержит DB_DATA_OLDER_THAN_24H и DB_PUBLICATION_OVERDUE
- WHEN показан checked либо unsupported CVE результат
- THEN оба предупреждения и сохранённый evaluatedAt доступны сразу, подробности сохраняют исходные DB timestamps и worker checkedAt; NextUpdate не назван сроком допустимости.

#### Scenario: Legacy без v2 evidence
- GIVEN получен принятый legacy отчёт без нового receipt
- WHEN показана информация базы
- THEN политика 14 дней не выдумывается и актуальная допустимость остаётся неподтверждённой.

### Requirement: Явный opt-in и совместимость legacy
API SHALL предоставлять view=report-v1 на существующих GET /api/v1/scans/:scanId/{vuln|sbom|results} и /api/v1/browser/scans/:scanId/{vuln|sbom|results}, сохраняя обе существующие owner-auth границы и legacy/no-view numeric cursor, limit 1–100 с default 50, порядок и envelopes. results обозначает Secrets; новые filter/sort параметры без view отвергаются 400 INVALID_REPORT_QUERY, а не молча игнорируются.

#### Scenario: Два режима чтения
- GIVEN владелец читает существующий сохранённый отчёт
- WHEN он отправляет legacy запрос без новых параметров либо явно выбирает view=report-v1
- THEN legacy остаётся совместимым; только opt-in получает новый page contract и opaque continuation, без нового сканирования или изменения сохранённых rows/evidence.

### Requirement: Глобальная операция до страницы
API SHALL валидировать полный сохранённый набор категории размером не более 1000 строк и выполнять filter → deterministic sort → slice над этим набором, не сортируя и не фильтруя только загруженную страницу и не скрывая повреждение/превышение bound как checked zero.

#### Scenario: Совпадение за прежней первой страницей
- GIVEN checked отчёт содержит 1000 строк и нужные строки находятся вне прежней первой страницы
- WHEN владелец задаёт report-v1 фильтр и сортировку
- THEN первая выбранная страница включает подходящие строки из полного набора в заданном порядке; исходный отчёт и его evidence не переписываются.

### Requirement: Размер страницы report-v1
API и интерфейс SHALL поддерживать только limit 5, 10, 25 или 50 с default 25 в report-v1, показывая выбор размера рядом с отчётом и используя его одинаково в запросе и подтверждённом page echo.

#### Scenario: Изменение размера
- GIVEN подтверждена страница CVE с limit=25
- WHEN пользователь выбирает 5, 10 или 50
- THEN старые строки и cursor history CVE сбрасываются, новый запрос начинается без cursor и диапазон подтверждается только после ответа нового размера; другие категории не меняются.

### Requirement: Полный итог и выбранные совпадения
API и интерфейс SHALL различать page.totalCount полного checked отчёта, page.matchedCount выбранного набора и page.returnedCount текущей страницы; существующие findingCount/componentCount/coverage totals остаются полными, а диапазон pager относится к matchedCount. page содержит ровно version=1, limit, offset, returnedCount, totalCount, matchedCount, sort и filters; offset/returnedCount — неотрицательные safe integers, returnedCount равен длине rows и не превышает limit, checked counts согласованы и matchedCount ≤ totalCount ≤ 1000.

#### Scenario: Проверено, но фильтр ничего не нашёл
- GIVEN checked категория содержит totalCount=72
- WHEN серверный фильтр подтверждает matchedCount=0
- THEN rows пусты, offset=0, returnedCount=0 и nextCursor=null, видны «нет совпадений» и сброс фильтра; полный итог 72 не заменён нулём и это не заявление об отсутствии риска.

#### Scenario: Проверка не выполнена
- GIVEN категория failed, unsupported, ожидается, отсутствует либо доступен только count без checked row dataset
- WHEN читается report-v1
- THEN исходные outcome/reason/coverage/evidence сохраняются, rows пусты, page.totalCount и page.matchedCount равны null, offset/returnedCount равны 0 и continuation отсутствует; unknown не подменяется checked zero. Отсутствующий owner report по-прежнему может дать 404, а не фиктивный пустой checked отчёт.

### Requirement: CVE severity как сохранённый факт
API SHALL фильтровать CVE только по сохранённой top-level finding.severity через optional duplicate-free CSV subset UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL и сортировать severity:desc (default) или severity:asc; UNKNOWN остаётся последним в обоих направлениях, ties разрешаются findingId ASCII ascending. Пропущенный либо полный набор нормализуется в filters={severity:null}, subset — в каноническом enum порядке; advisory maximum, vendor consensus или новый CVSS не вычисляются.

#### Scenario: LOW с конфликтующим CRITICAL источника
- GIVEN сохранённая severity=LOW, а отдельная source assessment=CRITICAL
- WHEN выбрана HIGH/CRITICAL subset или severity сортировка
- THEN принадлежность и порядок определяются сохранённым LOW, но при отображении этой строки конфликт и CRITICAL источника остаются видимы без hover; фильтр не выдаётся за сводный риск всех источников.

#### Scenario: UNKNOWN и полный набор
- GIVEN имеются LOW, HIGH и UNKNOWN findings
- WHEN сортировка меняется с desc на asc либо явно выбраны все пять severity
- THEN UNKNOWN остаётся последним, ties стабильны, а полный набор эквивалентен omitted filter и подтверждается null echo.

### Requirement: SBOM инвентарь без вымышленного риска
API SHALL применять к SBOM optional ecosystem=apk|npm и name длиной 1–128 ASCII по [A-Za-z0-9@._+/-]+ как AND-фильтры; name нормализуется lowercase и ищется literal ASCII case-insensitive substring без regex/wildcards. filters={ecosystem:apk|npm|null,name:string|null}; сортировки name:asc (default), name:desc, ecosystem:asc, ecosystem:desc детерминированы: name ties → ecosystem → version ascending, ecosystem ties → name → version ascending, version lexical, не semver.

#### Scenario: Смешанный регистр имени
- GIVEN сохранён SBOM пакет с подходящим именем
- WHEN пользователь отправляет name=PACKAGE-2 вместе с ecosystem=npm
- THEN применяется global literal поиск package-2 только среди npm, канонический lowercase echo принимается, а число пакетов не называется severity, числом CVE или доказательством безопасности.

### Requirement: Secrets rule и наличие строки без severity
API SHALL применять к Secrets только optional exact case-sensitive ruleId по [A-Za-z0-9._-]{1,80} и linePresence=known|unknown, со sorts ruleId:asc (default), ruleId:desc, line:asc, line:desc; filters={ruleId:string|null,linePresence:known|unknown|null}. known означает line!==null, включая 0; line numeric/null-last в обоих направлениях, ties → ruleId → findingId ascending; ruleId ties → findingId ascending. Rule ID остаётся opaque/hashed идентификатором, а line относится к результату, не к глобальной позиции файла.

#### Scenario: Нулевая и неизвестная строка
- GIVEN Secrets rows имеют line=0 и line=null
- WHEN выбран known либо сортировка line:desc
- THEN 0 считается известной строкой, null остаётся последним при сортировке; severity/category/raw secret/path фильтры не предлагаются и новые факты о них не выдумываются.

#### Scenario: Неверный ruleId в форме
- GIVEN пользователь ввёл whitespace, неподдерживаемую пунктуацию или более 80 символов
- WHEN он применяет Secrets фильтр
- THEN локальная проверка сообщает фиксированную понятную ошибку без echo введённого значения; не отправляется заведомо неверный query. Пустое поле означает отсутствие фильтра, валидный регистр не меняется.

### Requirement: Закрытый query contract
API SHALL принимать в report-v1 только single scalar nonempty occurrences разрешённых ключей view, limit, cursor, sort и фильтров выбранной категории, отвергая unknown, repeated, array/object, неверные enum/grammar/limit/severity subset значения фиксированным 400 INVALID_REPORT_QUERY; malformed/noncanonical/out-of-range cursor получает 400 INVALID_PAGINATION после owner read.

#### Scenario: Повторённые либо чужие ключи
- GIVEN запрос report-v1 содержит два limit, repeated severity, SBOM severity, Secrets name либо неизвестный ключ
- WHEN выполняется разбор запроса доступного owner report
- THEN запрос отвергается, а не выбирает одно значение, не игнорирует ключ и не запускает локальную подмену global фильтра.

### Requirement: Owner-first opaque continuation
API SHALL на каждом opt-in GET сначала авторизовать субъекта и прочитать owner-scoped существующий report, затем диагностировать query/cursor; cursor — canonical base64url UTF-8 JSON ровно {v:1,q,r,o}, не более 512 ASCII, q/r — 64 lowercase hex, o — safe integer 0..1000. q привязан SHA-256 к версии 1, subject, scanId, kind, нормализованным filters, sort и limit; r — к полному валидированному выбранному сохранённому snapshot, включая scan/report metadata и source-order rows, без текущих clocks. Это consistency token, не подпись, capability или авторизация; raw subject, report, secret и key в token не помещаются.

#### Scenario: Чужой report и валидный cursor
- GIVEN субъект не владеет scan, report отсутствует либо pruned
- WHEN он передаёт даже синтаксически корректный cursor
- THEN существующая owner/auth граница сохраняется, missing/foreign report даёт 404 до cursor diagnostics и чужие rows/counts/query сведения не выдаются; missing ledger остаётся 503 SCANNER_UNAVAILABLE.

#### Scenario: Query и snapshot несовместимы
- GIVEN owner report доступен и continuation синтаксически корректен
- WHEN изменены subject/scan/kind/filter/sort/limit либо сохранённый snapshot
- THEN query mismatch даёт 400 REPORT_CURSOR_QUERY_MISMATCH, snapshot mismatch — 409 REPORT_CURSOR_STALE; malformed token и offset больше matchedCount дают 400 INVALID_PAGINATION. Offset ровно matchedCount допустим как пустая terminal page без continuation; numeric legacy token в report-v1 не принимается.

### Requirement: Каноническое подтверждение страницы
Интерфейс SHALL принимать report-v1 только с закрытым корректным page echo, соответствующим effective query и запрошенному offset/limit, корректными rows/metadata/continuation и согласованными checked totals; membership duplication/overlap, cursor cycle, пустое continuation или несовместимый terminal/total отвергаются до публикации. nextCursor — выданный сервером opaque string либо null, не numeric offset; offset не становится частью постоянной query identity между страницами.

#### Scenario: Повреждённая следующая страница
- GIVEN подтверждена первая report-v1 страница
- WHEN приходит duplicate ID, overlap с прежней страницей, несовместимый matchedCount, cyclic cursor либо неверный filters echo
- THEN incoming rows не публикуются, visible и retained historical rows, confirmation, baselines, fingerprints, history, navigation и attempted cursor очищаются; восстановление начинается без cursor, не как ordinary transient retry.

### Requirement: Сброс выбранного report context
Интерфейс SHALL при применении фильтра, sort, limit, сброса выбора либо повторном применении того же выбора после ошибки очищать состояние выбранной категории и начинать с omitted cursor; effective normalized query входит в context вместе с subject/session generation/scan/kind/target/доступными report metadata. Поздний ответ старого контекста не подтверждает новую страницу; continuation следует только с тем же effective query, а смена видимости категории сама по себе его не сбрасывает.

#### Scenario: Фильтр меняется во время GET
- GIVEN следующая CVE страница ещё загружается либо показан C4 historical snapshot
- WHEN пользователь меняет HIGH на LOW или повторно применяет выбранный фильтр после ошибки
- THEN прежние visible/retained rows и cursor stacks CVE очищены, старый GET отменён/не публикуется, retry использует первый cursor нового контекста; Secrets/SBOM не смешиваются с CVE.

### Requirement: Строгий reset контракта отдельно от 503 и C4
Интерфейс SHALL классифицировать malformed JSON/wire/page/receipt/metadata и точные opt-in 400 INVALID_REPORT_QUERY, INVALID_PAGINATION, REPORT_CURSOR_QUERY_MISMATCH и 409 REPORT_CURSOR_STALE как payload-free strict-clear failures, включая восстановление из C4 historical snapshot. Удаляются visible и retained rows, count/range confirmation, baseline/fingerprints/history/navigation/attempted cursor; recovery начинает first cursor, invalid query требует исправления выбора с фиксированным actionable сообщением без raw payload/query/token echo. Legacy error compatibility не расширяется молча.

#### Scenario: Malformed v2 после исторического снимка
- GIVEN после C4 drift остался явно historical last-confirmed snapshot
- WHEN recovery получает неизвестную v2 version, missing dbPolicy, invalid warnings/usableUntil, malformed page либо один из точных opt-in query/cursor errors
- THEN даже historical rows очищены, navigation отключена, rejected payload не показан, дальнейшее восстановление начинает first cursor; metadata/query/membership failures не объявляются content-only C4.

#### Scenario: Обычная 503 не становится reset
- GIVEN report-v1 страница подтверждена либо показан допустимый same-context C4 historical snapshot
- WHEN GET получает ordinary network failure или 503 без смены доступа/контекста/metadata
- THEN обычный переход сохраняет last-confirmed rows/range и retry того же attempted cursor; C4 recovery сохраняет только прежний явно historical snapshot с disabled navigation и retry first cursor. Новая версия не превращает эти случаи в checked zero или успешное подтверждение.

### Requirement: Предоставленные Secrets timestamps
Интерфейс SHALL сохранять supplied validated Secrets checkedAt в opt-in report identity и сравнивать page/status stamps, когда оба предоставлены; отсутствие timestamp остаётся неизвестным, не создаёт выдуманную идентичность и не меняет legacy/no-view normalization.

#### Scenario: Timestamp изменён при неизменных строках
- GIVEN подтверждён Secrets report-v1 с предоставленным checkedAt
- WHEN следующий или повторный ответ меняет checkedAt при тех же row IDs/content либо противоречит предоставленному status stamp
- THEN это metadata drift со строгим очищением и first-cursor recovery, не C4 content-only exception; отсутствие stamp само по себе не подменяется текущим временем.

### Requirement: Fixture без имитации global controls
Интерфейс SHALL явно объявлять global report-v1 controls unsupported для fixture transport, не игнорируя переданные options и не фильтруя/сортируя локальную страницу под видом полного отчёта.

#### Scenario: Просмотр synthetic fixture
- GIVEN отчёт читается через fixture transport без server-global capability
- WHEN пользователь видит toolbar или transport получает report-v1 options
- THEN глобальные controls недоступны с объяснением unsupported, options не принимаются молча; legacy чтение fixture и честное page-local no-match остаются отдельными от проверенного server-global результата.

## Non-goals
- Не менять scanner/worker, image contract, DB schema, auth/session transport, admission, quota, consent, source-citation verification или backend ИИ. Новое API-владение ограничено opt-in read-only report-v1 saved-report query/page contract; no-view и browser CVE v2 closed reading сохраняются.
- Не заменять DOC1/2/6/9, их неприменённые дельты и future areas; не объявлять полный P0 или весь UI-план принятым.
- Не выдумывать отсутствующий report ID или Secrets timestamp: используются только предоставленные status/target/check timestamps/counts/scanner/page identities и новый opt-in consistency token; owner authorization обязательна на каждом GET.
- Не добавлять cursor signing keys, provider calls, повторное сканирование, bulk autoload, totalPages/random access или локальную имитацию global sort/filter.
- Не обещать распознавание полного удаления всех v2 markers во всех копиях checked archive wire: legacy-equivalent all-copy stripping может быть неотличимым; сохраняется явная unconfirmed legacy-policy label, без выдуманного protocol/signature gate.
- Browser fixtures и author synthetic tests не подтверждают live readiness, native snapshot/HTTP integration, ручную screen-reader проверку, Safari/Firefox, mobile browser, production deploy или безопасность всех произвольных строк.
- Наличие локального draft не означает применённую source41 delta или закрытую задачу. Spec application и narrow closure остаются отдельными действиями после восстановления MCP; история applied c8b710c1 не переписывается.
