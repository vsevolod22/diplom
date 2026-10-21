# CVE advisory/report: локальный exact-кандидат и достоверные находки — целевой контракт

## Purpose
Полный целевой контракт отдельного домена `cve-advisory-report` для DIP-FEAT-1 / DIP-TASK-2 по judgement 4ecad555-be7c-4171-8e66-570d78dffa12: этап A — узкая LOCAL активация квалифицированного exact nginx, этап B — фактические advisory/CVSS/источники в общих «Находках». Это target, не заявление о реализации или deployment. DIP-DOC-1 v4 и его десять P0 baseline requirements сохраняются без изменения; этот документ не заменяет их и не применяется вместе с непроверенными будущими частями. Approved/unapplied db14160a-85f5-42f6-b112-a9b2138dc466 остаётся отдельной неизменённой историей.

## Requirements

### Requirement: Граница подтверждения целевого отчёта
Система SHALL не представлять предлагаемую локальную nginx-активацию или новые advisory/CVSS/ссылки как подтверждённые возможности лишь на основании наличия целевой спецификации.

#### Scenario: Target ещё не принят как реализованный
- GIVEN существует целевая дельта без доказанной реализации соответствующего этапа
- WHEN оценивается доступность отчёта или admission
- THEN применяется фактическая серверная policy и подтверждённое покрытие; delta не является qualification, фиктивным результатом или основанием закрыть DIP-TASK-2.

### Requirement: Сохранение авторизованного P0 baseline
Система SHALL сохранять авторизацию и ownership, закрепление digest/platform до enqueue, readiness, subject-scoped идемпотентность, registry-only egress, независимые Secrets/SBOM и bounded owner status/list/results/SSE/cancel при расширении advisory/report.

#### Scenario: Replay и посторонний субъект
- GIVEN прежний subject/idempotencyKey имеет сохранённый нормализованный запрос и immutable receipt, tag изменён, а gateway недоступен
- WHEN владелец повторяет запрос, меняет его checks либо другой субъект запрашивает отчёт
- THEN точный replay возвращает прежний scanId без разрешения tag/второго задания, изменённый запрос даёт конфликт, чужой отчёт не раскрывается; новый запрос требует актуальной готовности. Anonymous/foreign ответы остаются безопасными 401/404, Origin/permission/quota guards не обходятся.

### Requirement: Локальная активация только exact квалифицированного кандидата
Система SHALL ограничивать дополнительный LOCAL nginx-профиль серверно скомпилированной квалификацией `registry-1.docker.io/library/nginx`, child `sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3`, config `sha256:dc73b49f5124cf2ee538dfbdfbd121f0b4ccdcb20fea30f3a81bd477c02e2bb5`, `linux/amd64`, Trivy 0.69.3 и доказанными check sets/версиями policy, сохраняя default AppModule и прочие deployments закрытыми для nginx.

#### Scenario: Local qualified versus поддельный профиль
- GIVEN привязка применимых proof/review к source/check/resource identity проверена, новая local composition рассмотрена и активирована
- WHEN существующий аккаунт выбирает exact-кандидат либо caller подставляет другой child/config/platform/repository/check-set
- THEN exact-запуск проходит обычные auth/DB/readiness/fencing guards, другой запрос отклонён до enqueue; arbitrary tag/repository, env-defined target, generic enable flag и proof-only test key не допускаются. Qualification API и worker совпадает; entrypoint образа не исполняется.

### Requirement: Серверная eligibility сохранённого предложения
Интерфейс SHALL разрешать запуск сохранённого предложения только по текущей серверной eligibility exact identity/check-set с повторной проверкой при POST.

#### Scenario: Возврат к предложению
- GIVEN сохранено серверное предложение exact-кандидата, затем local profile активирован либо DB/readiness изменились
- WHEN пользователь возвращается к предложению
- THEN готовый квалифицированный кандидат реально запускается без обязательного нового поиска, неподдерживаемый/неготовый disabled с безопасной причиной; persisted scannable не заменяет POST policy, target не переключается на иной tag/digest. UI не hardcode-ит поддержку nginx.

### Requirement: Проверяемая immutable identity и закрытый egress
Система SHALL сохранять проверку manifest/config/layer bytes/hash/platform и receipt identity на всех стадиях с exact HTTPS registry/token/blob policy, all-answer public-IP DNS, numeric dial/TLS, bounded redirects и repository-scoped bearer без direct fallback/credential forwarding.

#### Scenario: Подмена или запрещённый endpoint
- GIVEN hash/config/diffId/platform отчёта не совпадает либо redirect/realm/DNS ведёт к запрещённому IP/host
- WHEN API или worker получает образ и сверяет scanner evidence
- THEN соединение или stage безопасно отклоняется без credentials/checked чужого результата; fabricated RepoDigests, Docker socket/daemon, host mounts и расширение egress не используются.

### Requirement: Численные ограничения квалифицированного исполнения
Система SHALL сохранять no-shell fixed argv/minimal env и версионированные caps: RAM=total RAM+swap=1073741824 bytes, cgroup swap.max=0, CPU1/PIDs128, tmpfs16MiB/512MiB, wire112MiB/160requests/180s подготовки, 32layers/32MiB compressed per layer/96MiB compressed total, 128MiB expanded per layer/256MiB expanded total, 50000 tar entries/64MiB file/64KiB extension/512B fields/1024PAX records, archive272MiB/logical scratch448MiB, stdout Secrets1000000B/SBOM2000000B/CVE8000000B, stage120s/attempt600s и существующий627s fenced lease.

#### Scenario: N N+1 и cleanup
- GIVEN вход/выход/ресурс достигает N либо N+1 или scanner прерван
- WHEN исполняется bounded pipeline
- THEN действуют byte/hash/tar/decompression/time/scratch guards и безопасный kill/owned cleanup, N+1 не становится truncated checked; caps не повышаются ради candidate/advisory. Sampled logical audit не объявляется per-write kernel quota, физический tmpfs остаётся hard bound; peak на1GiB не означает headroom или SLA.

### Requirement: Свежая закреплённая locally-attested DB
Система SHALL проверять production-pinned signature/key/OCI-layer-DB-metadata hashes/schema/freshness/RO inode identity при новом CVE admission, использовании, после scanner и перед fenced commit, сохраняя фактическую DB identity результата и обозначая local attestation как решение оператора, не Aqua authentication.

#### Scenario: Admission отказ и elapsed expiry
- GIVEN DB missing/stale/tampered/signature/schema-invalid при новом запросе либо реально истекла после enqueue/во время scanner/перед commit
- WHEN соответствующий guard выполняется
- THEN invalid admission не создаёт задания; принятый CVE получает failed/DB_UNAVAILABLE без checked/count, самостоятельный CVE — failed, combined с checked Secrets/SBOM — partial. Admission readiness не заменяет execution/write validation, legacy GET не получает identity текущего release вместо исторического.

### Requirement: Сохранение bounded host-only refresh модели
Система SHALL сохранять разрешённый bounded HTTPS/GHCR→validation/conversion→host-local signing→immutable RO activation/rollback flow без worker DB network/private key и без JWT/volume reset.

#### Scenario: Ошибка активации release
- GIVEN новый immutable candidate не прошёл verification либо health/post-switch check отказал
- WHEN операторский publisher выполняет switch
- THEN действует fail-closed/rollback к пригодному свежему prior release без смешения stage identities; changed digest/current health/no-op/unit simulation не объявляются controlled NEW rotation/rollback evidence.

### Requirement: Независимые outcomes и честная OS граница
Система SHALL сохранять отдельные requested outcomes checked/unsupported/not_authorized/failed/skipped с безопасными reasons, scanner/check/DB версиями и временем, не объявляя OS/EOL/Node coverage по tag или количеству findings.

#### Scenario: Неполный результат
- GIVEN один check failed, другой фактически checked, либо required OS evidence malformed/unknown/missing
- WHEN формируется итог
- THEN partial требует хотя бы один checked, failed — ни одного, completed — все requested checked; malformed/unknown required evidence failed, подтверждённый EOL unsupported/OS_EOL. Отозванный check not_authorized и не исполняется, unrequested skipped; APK CVEs/Node executable не подтверждают npm coverage.

### Requirement: Атомарная forward-only долговечность
Система SHALL сохранять findings/metadata/independent outcomes/versions/times/terminal event атомарно только текущей fenced попыткой через forward-only migration без reset или повышения legacy coverage.

#### Scenario: Legacy restart и late writer
- GIVEN legacy строки и актуальная попытка, а старая lease потеряна или scan отменён
- WHEN выполняются migration/reopen/commit/owner GET/SSE/reload
- THEN прежние IDs/ownership/idempotency/coverage сохраняются, late write не меняет snapshot и не дублирует finding/event, rollback/retention/backup остаются согласованными; сетевой lookup не выполняется внутри terminal transaction.

### Requirement: Общие видимые находки
Интерфейс SHALL показывать CVE и Secrets внутри одного видимого раздела «Находки», используя реальные независимые datasets, а SBOM оставлять инвентарём.

#### Scenario: CVE-only или Secrets0 плюс CVE
- GIVEN owner report имеет проверенные CVE и отсутствующие либо нулевые Secrets
- WHEN открывается деталь, выбираются Все/CVE/Secrets или выполняется reload
- THEN CVE count и первая страница карточек находятся в общей зоне вне обязательного аккордеона/нижней секции/закрытого mobile фильтра; CVE-фильтр выбирает CVE dataset, не secret-only массив, дублирующей CVE-секции нет.

### Requirement: Независимые страницы и честные totals
Интерфейс SHALL сохранять отдельные server totals/cursors/loading/error/query scopes CVE и Secrets, различая полный category count, filter match count и загруженную страницу.

#### Scenario: Фильтр пагинация и смена субъекта
- GIVEN категории имеют независимые продолжения и server totals
- WHEN пользователь листает CVE, меняет фильтр, получает page error либо меняет scan/subject
- THEN Secrets cursor не меняется, cached/stale pages не смешиваются и не дублируются; page-local фильтр явно помечен, обещанный global фильтр проверяет весь server набор. «Нет совпадений» со сбросом не заменяет scan total нулём, частично известные categories не суммируются в подтверждённый общий count.

### Requirement: Неизвестность не является нулём
Интерфейс SHALL отличать confirmed checked zero от queued/running, failed, unsupported, skipped, not_authorized, identity mismatch и HTTP/strict parsing failure.

#### Scenario: Partial или настоящий ноль
- GIVEN CVE failed/DB_UNAVAILABLE при checked Secrets/SBOM либо имеется сохранённый checked результат с совпадающими digest/platform и count0
- WHEN владелец открывает или перезагружает отчёт
- THEN в первом случае показаны безопасная причина и неизвестное число CVE с независимыми успешными результатами; только во втором — «0 обнаружено в проверенном покрытии», без заявления общей безопасности образа.

### Requirement: Фактические advisory поля и происхождение
Система SHALL передавать реально полученные Title/Description подтверждённой CVE как redacted plaintext с source/scanner/DB provenance и известным исходным языком, явно сохраняя missing/invalid/redacted/truncated состояния.

#### Scenario: Описание имеется либо отсутствует
- GIVEN реальный Trivy advisory содержит английский текст либо Title/Description missing/null/empty/invalid/полностью удалены redaction
- WHEN metadata проходит normalizer→durable storage→owner API→strict browser→reload
- THEN безопасный текст сохраняет смысл/язык, неизвестный язык не угадывается, missing — «Не предоставлено источником», redacted — «Недоступно после очистки», truncated помечен; package/CVE ID/шаблон/LLM/придуманный перевод не подменяют описание. Intake остаётся CVE-only: GHSA/BDU/non-CVE ID может быть проверенной source metadata существующей CVE, но не новой finding.

### Requirement: Единый UTF-8 metadata budget
Система SHALL ограничивать новую metadata единым профилем: Title512B, Description4096B, source label64B, vector256B, URL2048B, максимум16 source-version assessments и8references на finding, весь сериализованный UTF-8 JSON enrichment envelope ≤16384B/finding и ≤1048576B/scan включая ключи/escaping/статусы.

#### Scenario: Границы и исчерпание scan budget
- GIVEN поле/массив/envelope достигает N или N+1, включая многобайтный текст/JSON escaping
- WHEN normalizer работает в стабильном порядке findings/assessments/references
- THEN UTF-8-safe truncation/optional omission детерминированы и явно отмечены, envelopes укладываются в caps; ограничение конфликтующих assessments обозначено, не silently lost. Core finding/ID/count/coverage не удаляются, report/page caps не увеличиваются и scan budget не сбрасывается при pagination.

### Requirement: Redaction до сохранения и вывода
Система SHALL допускать только allowlisted bounded redacted advisory plaintext до SQLite/API/SSE/audit/log/UI и существующих LLM sinks без исполнения HTML/Markdown/скриптов/инструкций источника.

#### Scenario: Canary и HTML
- GIVEN недоверенная metadata содержит credential/secret-canary, control/bidi payload, HTML/Markdown/script/img-event или signed URL
- WHEN результат нормализуется и выводится
- THEN опасные значения не попадают сырыми в persist/response/log/DOM, текст escaped и не создаёт iframe/img/link execution; плохая optional metadata не стирает core finding, raw stdout/stderr/error fallback не публикуется.

### Requirement: Source-associated CVSS и явные конфликты
Система SHALL сохранять отдельные source/version reported assessments одной finding с nullable finite baseScore0..10, vector и доступными severity/fix/provenance полями, отображая содержательные расхождения без maximum/last-write-wins или отказа всего scan из-за конфликта источников.

#### Scenario: Два источника и стабильный count
- GIVEN одна прежняя identity имеет две разные оценки severity/fix/CVSS, score0 или неизвестные поля
- WHEN выполняются normalization/dedup/persist/reopen/owner HTTP/browser/reload
- THEN остаётся одна finding/count1 с обеими bounded source assessments и явным конфликтом, finite0 не теряется; разные installed version/location остаются разными findings, порядок metadata не меняет ID/count. Missing fixed version не изобретается, severity source не подменяет CVSS source, legacy findingId не переписывается.

### Requirement: Семантика версии и vector CVSS
Система SHALL валидировать vector по реально реализованному version-specific контракту обязательных метрик/значений/уникальности/prefix, не угадывая version из V3Score и не заменяя reported score вычислением из severity/vector.

#### Scenario: Невалидная или неполная оценка
- GIVEN score NaN/Infinity/string/вне0..10, score без vector, vector без score либо malformed/duplicate/version-mismatched/unsupported vector
- WHEN строится assessment и calculator action
- THEN invalid/missing поле неизвестно, не0; остальные валидные поля/assessments и core finding сохраняются, invalid vector не даёт prefill. Подтверждённое отдельной проверкой расхождение score/vector обозначается без исправления reported score; CVSS2.0/3.0/3.1/4.0 не объявлены автоматически всеми поддержанными.

### Requirement: Canonical navigation отличается от verified record
Система SHALL выдавать только серверно валидированные HTTPS references с exact host/path/query policy без userinfo/IP literal/нестандартного port/secret query/redirect wrappers, различая canonical navigation и independently verified advisory mapping/content/score.

#### Scenario: CVE.org NVD и произвольный URL
- GIVEN валидный CVE ID допускает canonical CVE.org/NVD template, а scanner References/PrimaryURL содержит arbitrary URL, suffix/Unicode-host trick, опасную схему или encoded control
- WHEN карточка показывает ссылки
- THEN canonical link помечен навигацией без утверждения проверенного существования/содержимого/score записи, vendor/advisory link требует подтверждённой authority и соответствия CVE; небезопасный URL отбрасывается до хранения и не становится fetch target. Source authority задаётся server policy, не raw DataSource URL.

### Requirement: Внешние ссылки открываются только пользователем
Интерфейс SHALL открывать разрешённую external reference только по явному действию пользователя с noopener/noreferrer без автоматического advisory DNS/fetch/proxy/prefetch и передачи приватных report данных или credentials.

#### Scenario: Mount hover и reload
- GIVEN карточка содержит безопасную reference
- WHEN она mounted/expanded/hovered/reloaded либо пользователь открывает ссылку
- THEN до действия пользователя сетевой advisory lookup не происходит, при действии передаются только разрешённые URL данные без cookies/token/scanId/referrer; reference не вводит worker egress или mandatory online fetch legacy отчёта.

### Requirement: Русский источник только по реальному БДУ mapping
Система SHALL показывать конкретную карточку БДУ ФСТЭК только при independently verified реальном CVE-to-BDU record mapping с canonical URL/record ID/provenance/датой проверки.

#### Scenario: Соответствие имеется либо неизвестно
- GIVEN первичное соответствие подтверждено либо mapping missing/противоречив/непроверен
- WHEN показывается русский источник
- THEN только подтверждённая запись имеет direct link с отдельными BDU ID и CVE; иначе — «Проверенный русский источник для этой CVE недоступен». CVE не вставляется в придуманный БДУ URL, general search не выдаётся за record/перевод, автоматический внешний lookup не запускается.

### Requirement: Реальный calculator не является CVE источником
Интерфейс SHALL предлагать только реально проверенный trusted calculator совместимой CVSS версии, отдельно маркированный инструментом расчёта по vector, а не advisory/русской карточкой/подтверждением score CVE.

#### Scenario: Prefill подтверждён либо нет
- GIVEN адрес/версия calculator проверены и vector семантически валиден
- WHEN пользователь выбирает calculator
- THEN prefill передаёт только разрешённые version/vector после actual URL/vector roundtrip; без доказанного prefill доступен честно общий совместимый calculator и копирование vector. Без vector/совместимого инструмента action unavailable; FIRST3.1 page read сам по себе не доказывает prefill или русский CVE record.

### Requirement: Legacy совместимость и применимые findings
Система SHALL добавлять metadata без изменения findings IDs/counts/immutable target/исторического scanner/DB coverage и без синтеза advisory для legacy строк.

#### Scenario: Один report и полная DB
- GIVEN один реальный scanner/image/DB snapshot содержит N unique findings, а legacy report не имеет новых полей
- WHEN выполняются enrichment/migration/reopen/pagination/reload
- THEN тот же report сохраняет N/IDs/digest/platform, legacy показывает missing metadata без failure/повторного scan/backfill из новой DB; большая upstream DB не добавляет unrelated CVEs. Новый scan другой DB имеет фактический count, не обязан повторять исторические4/209.

### Requirement: Реальная stage A приёмка локального кандидата
Приёмка SHALL подтверждать привязку принятых proof/review к compiled exact qualification и новую LOCAL activation через текущую production-anchor fresh RO DB, существующий аккаунт и runtime1GiB/no-swap guards.

#### Scenario: Existing-account local workflow
- GIVEN применимые supported-pin launch/negative proofs приняты, новая activation diff рассмотрена и JWT/env/key/volumes сохранены
- WHEN оба base Compose плюс отдельная local operator composition развёрнуты и существующий аккаунт выполняет UI select→create→report→reload→logout
- THEN target/check/resource/API-worker qualification совпадает, guarded HTTP/Trivy/fenced ledger дают реальный report; при отказе rollout откатывается, default deployments остаются closed. Disposable proof account/test key/isolated209 report не подменяют эту deployed workflow acceptance.

### Requirement: Реальная stage B приёмка advisory UI
Приёмка SHALL подтверждать count-preserving normalizer→обе применимые durable формы→owner HTTP→actual Chromium «Находки»→reload на разрешённом pinned old-Alpine и дополнительно активированном exact local candidate.

#### Scenario: Реальные positive и negative состояния
- GIVEN авторизованный реальный scan с ненулевыми применимыми CVE и зафиксированными image/scanner/DB identities
- WHEN owner открывает CVE-only/combined, descriptions/assessments/links, страницы/фильтр и reload, а чужой аккаунт запрашивает данные
- THEN CVE видны в общей зоне, metadata фактическая либо точно unavailable, N/IDs не изменены, foreign/anonymous безопасно404/401; missing/legacy/partial/page-error/unknown/XSS/canary/bounds/conflict состояния проверены отдельно. Unit/JSDOM/synthetic fixtures дополняют, не заменяют actual HTTP/Trivy/Chromium; BDU direct-link positive требует real primary mapping evidence/date.

### Requirement: Поэтапное применение только подтверждённого поведения
Спецификация SHALL становиться описанием реализованного поведения только по фактической stage-specific acceptance, без wholesale apply смешанного future target или закрытия полной DIP-TASK-2 из частичного среза.

#### Scenario: Реализован только один этап
- GIVEN stage A принят, а stage B либо whole-task критерии ещё не подтверждены
- WHEN оформляется applied spec revision или закрытие работы
- THEN отдельный полный evidence-backed resulting body содержит только подтверждённое поведение и явные оставшиеся границы; эта полная target delta не применяется для объявления всех stages implemented. Feature-sourced proposal не заменяет task-level strict-close evidence.

## Non-goals
- Arbitrary tags/repositories/platforms, private registries/credentials, host/container-runtime/socket/mount доступ, новый egress, generic non-CVE intake, advisory scraping/fetch, AI enrichment/перевод, выдуманные CVE/CVSS/fixed versions/БДУ mappings не вводятся.
- Full DIP-TASK-2 не завершена этим target. Remote npm dependency/advisory-positive, полные две provenance assessments/conflict-preserving dedup/redaction по всей прежней sink-матрице и controlled NEW upstream rotation/rollback остаются отдельно pending; минимальный source-associated advisory conflict контракт не объявляет всю матрицу выполненной.
- Не редактировать owned другим integrator `server/api/src/image-config`, `oci/pinned-image-config.ts`, `worker/image-config-runner`, shared UI согласовывать; не включать foreign notices в изменения. JWT/env/key/volumes и оба Compose baseline сохраняются без reset/stand:auth.
- Не переписывать или применять db14160a wholesale, не менять DIP-DOC-1/P0 baseline, не создавать новые tasks/plans или обязательный human gate. Standing LOCAL permission уже предоставлено; require_proposal_approval=false не требует ожидания человека.

## Датированное evidence и последовательность
1. FIRST — evidence/source/check/resource binding и новая compiled LOCAL composition/eligibility с applicable review, production-pinned fresh RO DB/rescan и existing-account UI workflow. SECOND — coherent advisory/UI implementation и actual stage B acceptance. На момент подготовки target ни новая local composition, ни advisory не объявлены реализованными.
2. Прочитанное DIP-ARTF-28 на HEAD4aad94d7: четыре newest during/precommit real-wall-clock expiry/redaction cases 4/4 PASS, failures/errors/skips0, 473.110s; actual1592160951-byte copied snapshot/mutation isolation и1GiB/no-swap guards PASS. Это больше не pending four-case gap, но не новый positive209 rerun, не universal all-sink certification и не один uninterrupted full matrix. Предшествующие C4-1/review истории сохраняются; повторный632s proof/новый approval cycle принятого старого diff не требуется.
3. Исторические209 normalized OS CVEs/72APK/Alpine3.23.3 — датированное positive evidence exact-кандидата, не фиксированный текущий count/npm-positive. Свежесть DB проверяется при actual activation/scan; локальная подпись не Aqua authentication. Known SSE67, unclassified прежние positive/queued failures и parent kernel OOM не объявлены исправленными/доказанными; новый unconditional parent-OOM gate не вводится.
4. Canonical CVE.org/NVD links — policy navigation, не verified advisory contents. FIRST3.1 calculator page ранее прочитана архитектором; vector-prefill roundtrip и конкретный CVE→БДУ mapping не проверены. Их availability не выдумывается. Этот spec-author шаг выполняет только документальное чтение/валидацию, не новые runtime/source-link tests.
