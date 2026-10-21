# P0: авторизованный registry image scan и достоверный отчёт

## Purpose
Зафиксировать текущий исходный контракт registry-only image scan и отдельно поставленный optional `public-hub-amd64-v1`, не подменяя приёмку наличием спецификации. Полное результирующее тело построено поверх live DIP-DOC-1 v5; его 23 legacy requirements сохранены. Старый nginx-first target, Alpine inventory, default-off exact admission, legacy DB freshness и 1 GiB envelope относятся только к legacy-профилям; public имеет отдельные composition, receipt, bounds и DB policy ниже. Общие authorization/ownership, immutable identity, egress, redaction, durability и применимые qualification gates действуют для обоих профилей.

Current-source поддерживает bounded official/namespaced Docker Hub image-only/linux/amd64, самостоятельные и combined Secrets/SBOM/vuln, optional config, 11 нормализуемых ecosystems и строго ограниченные Debian TEMP advisories. Это не все образы/ОС/платформы и не blanket qualification. Датированное native evidence для Debian и Node существует (2026-10-18); оно не является повторным запуском, сегодняшней DB readiness или full DIP-TASK-2 acceptance. `checked` означает выполненную проверку в заявленной области, не безопасность. Отмена всех image-профилей остаётся `cancelled` с durable subset, а не `partial` по числу завершённых checks. LLM implementation и docs исключены из этой сверки.

## Requirements

### Requirement: Авторизованный закреплённый запуск
Система SHALL принимать `POST /api/v1/scans` только у субъекта с правом image scan и для поддерживаемых reference, scope, checks и platform; после разрешения manifest SHALL сохранять digest/platform до постановки задания и возвращать 202 с `scanId`, `statusUrl`, `eventsUrl` только при готовой изолированной цепи. Неподдерживаемый запрос SHALL отклоняться без задания.

#### Scenario: Переназначение tag после приёма
- GIVEN уполномоченный субъект отправил поддерживаемый tag и получил 202 с digest A для linux/amd64
- WHEN тот же tag начинает указывать на digest B до получения слоёв сканером
- THEN задание и результат относятся к A и linux/amd64, а не к B.

#### Scenario: Цепь недоступна
- GIVEN для нового запроса worker или контролируемый egress недоступен
- WHEN субъект отправляет новый допустимый запрос
- THEN новый scan не создаётся и возвращается безопасный отказ 503.

### Requirement: Идемпотентность субъекта
Система SHALL возвращать прежний scanId при повторе того же `(subject, idempotencyKey)` с тем же нормализованным запросом до повторного разрешения tag или проверки текущей готовности; при изменении параметров SHALL возвращать конфликт без второго задания.

#### Scenario: Повтор при изменённом tag и отключённом gateway
- GIVEN исходный запрос был принят и сохранён, после чего tag сменился, а gateway временно отключён
- WHEN тот же субъект повторяет запрос с тем же ключом и параметрами
- THEN получает прежний scanId и ссылки без повторного разрешения tag или второго задания; новый ключ не получает 202.

### Requirement: Защита registry egress
Система SHALL разрешать только явно перечисленные registry, token и blob hosts и проверять полный набор DNS-адресов на каждом соединении API и scanner с подключением к проверенному адресу; запрещённые IP, redirects и auth realms SHALL отклоняться без отправки credentials и без обхода через прямое соединение.

#### Scenario: Запрещённое перенаправление или DNS rebinding
- GIVEN допустимый registry направляет manifest, blob или token на запрещённый адрес либо разрешённое имя меняет DNS на запрещённый IP
- WHEN API или scanner пытается выполнить запрос
- THEN запрещённое соединение не устанавливается, credential не передаётся и видна только безопасная ошибка.

### Requirement: Image scan без Docker daemon
Система SHALL выполнять поддерживаемую проверку закреплённого registry digest/platform без доступа API или worker к Docker socket и без переключения scanner на локальный Docker Engine.

#### Scenario: Доступный daemon на хосте
- GIVEN на хосте работает Docker daemon
- WHEN выполняется image scan или попытка прямого обхода сетевой политики из API либо worker
- THEN задание использует registry-only источник, а socket и прямой daemon-доступ недоступны.

### Requirement: Проверяемый результат узкого среза
Система SHALL выдавать только очищенные результаты фактически выполненной проверки secrets с состоянием покрытия, безопасной причиной отказа и разграничением по субъекту; отсутствие находок SHALL не означать выполненные CVE или SBOM проверки.

#### Scenario: Чистый образ и чужой scanId
- GIVEN проверка secrets поддерживаемого образа успешно завершена без находок
- WHEN владелец просматривает результат, а другой субъект запрашивает тот же scanId
- THEN владелец видит ноль находок только для выполненной secrets-проверки, а другой субъект не получает статус или результаты.

### Requirement: Отдельный SBOM образа
Система SHALL принимать самостоятельную `sbom` и квалифицированные сочетания checks поддерживаемого закреплённого образа, выдавая ограниченный перечень установленных пакетов и версию ОС только после фактически выполненного CycloneDX-сканирования с проверкой ожидаемых identity/platform и Alpine inventory; SBOM SHALL не объявляться проверкой CVE.

#### Scenario: Успешный инвентарь Alpine
- GIVEN субъект с доступом запустил отдельно `sbom` для закреплённого Alpine linux/amd64
- WHEN изолированный scanner подтверждает идентичность образа, ОС и пакетов
- THEN его авторизованный отчёт показывает проверенное image-покрытие, версию scanner и постраничный инвентарь, но не количество CVE.

#### Scenario: CVE без базы и независимое сочетание
- GIVEN проверенная актуальная CVE DB отсутствует, а Secrets/SBOM доступны для квалифицированной цели
- WHEN субъект запрашивает `vuln` отдельно либо в сочетании с другими checks
- THEN запрос отклоняется до создания задания без «0 CVE»; отдельно квалифицированное сочетание без `vuln` не требует CVE DB и может выполняться независимо.

### Requirement: Отказ SBOM не означает пустой инвентарь
Система SHALL хранить ошибку сканирования SBOM отдельно от успешно проверенного инвентаря; ошибка SHALL показывать безопасную причину без `checked`, числа пакетов или вывода scanner.

#### Scenario: Сбой и устаревшая попытка
- GIVEN SBOM scanner завершается с ошибкой либо прежняя попытка теряет право завершить задание
- WHEN владелец запрашивает состояние и SBOM
- THEN ошибка показана без списка подтверждённых пакетов, а устаревшая попытка не подменяет результат актуальной.

### Requirement: Разграничение SBOM-отчёта
Система SHALL отдавать SBOM-отчёт постранично только владельцу scanId через авторизованный API либо зарегистрированную сессию локального браузерного стенда; другим субъектам и анонимным посетителям отчёт недоступен.

#### Scenario: Два зарегистрированных аккаунта
- GIVEN Alice и Bob имеют разные действующие сессии, а SBOM-скан принадлежит Alice
- WHEN оба запрашивают один и тот же `/sbom` по scanId
- THEN Alice получает ограниченные страницы пакетов, а Bob получает 404 без данных чужого задания.

### Requirement: Закреплённая цель в авторизованном статусе
Система SHALL отдавать сохранённые digest и platform только владельцу задания в `GET /api/v1/scans/:scanId`, не выводя их повторно из изменяемого tag.

#### Scenario: Владелец и посторонний субъект
- GIVEN задание сохранено с digest A и linux/amd64, а tag после приёма переназначен
- WHEN владелец и посторонний субъект запрашивают статус по одному scanId
- THEN владелец получает A и linux/amd64, а посторонний получает 404 без раскрытия метаданных.

### Requirement: Авторизованный постраничный список
Система SHALL отдавать `GET /api/v1/scans` только субъекту с действующей авторизацией, ограничивать размер страницы и возвращать лишь его задания с продолжением, закреплённой целью и состоянием, без ключей идемпотентности и чужих записей.

#### Scenario: Страницы двух субъектов
- GIVEN Alice и Bob имеют разные задания, а Alice имеет более одного задания
- WHEN Alice запрашивает список постранично, а Bob открывает тот же маршрут с собственным токеном
- THEN каждый получает только свои задания и корректный nextCursor; неавторизованный запрос отклоняется, отсутствие сессии не считается пустым списком.

### Requirement: Версионированный nginx-first admission
Система SHALL сохранять `library/alpine` baseline и держать новый профиль `registry-1.docker.io/library/nginx` default-off, ограничивая его image-only, linux/amd64, квалифицированными immutable child digest/platform и независимо доказанными checks в версионированной серверной политике.

#### Scenario: Непроверенный target
- GIVEN discovery нашёл иной repository, неквалифицированный nginx digest или tag серверно разрешился в новую identity
- WHEN пользователь запускает scan через UI или напрямую
- THEN задания и 202 нет; новый tag/digest требует отдельной qualification той же матрицей, generic name validator и discovery не открывают admission.

### Requirement: Проверенная immutable identity всех стадий
Система SHALL проверять bytes/hashes index, единственный выбранный linux/amd64 child manifest и config до enqueue и сопоставлять Secrets/SBOM/CVE результаты с ожидаемой repository/digest/platform, сохраняя tag лишь как исходную метку.

#### Scenario: Подмена или неоднозначность
- GIVEN manifest/config hash неверен, platform неоднозначна либо scanner report относится к другому digest/repository/architecture
- WHEN resolver или parser проверяет identity
- THEN target не принимается либо stage получает безопасный failed без checked/persist чужого результата; entrypoint образа не исполняется.

### Requirement: Изолированный proof перед production opt-in
Система SHALL разрешать operator-only активацию фиксированного bounded candidate в отдельной изолированной proof конфигурации того же кода с поставляемыми authorization/TLS/egress/DB/resource guards, а production opt-in SHALL требовать применимые remote/browser/negative gates без skips и три независимых review security/correctness/spec.

#### Scenario: Initial qualification nginx
- GIVEN production профиль выключен и реальный доступный nginx Alpine tag серверно закреплён за child digest/config/linux/amd64
- WHEN authenticated cookie/nginx/API ingress выполняет реальные standalone Secrets/SBOM/CVE и combined через Trivy 0.69.3, worker, SQLite, owner report и Chromium/reload
- THEN evidence фиксирует policy/scanner versions/argv, target digests/platform, DB release/hashes/attestation/freshness/time, реальные SBOM компоненты и валидный Secrets outcome; initial CVE opt-in требует хотя бы один фактически возвращённый CVE с package/installed/fixed-or-unknown/severity source/provenance. Synthetic JSON/local tar/metadata rewrite не заменяют remote proof; Secrets может честно иметь 0.

#### Scenario: Независимый выпуск и повтор proof
- GIVEN доказана только часть checks либо существенно изменены scanner/parser/admission/resource policy или переключён DB release
- WHEN оценивается выпуск или повторяется remote proof
- THEN включаются лишь доказанные checks, CVE без initial positive остаётся закрытым; повтор фиксирует фактические outcomes, позднейший валидный CVE=0 не фабрикуется и не отменяет исторический positive proof, failed/unsupported не считается checked. Публичного test route или bypass guards нет.

### Requirement: Независимые outcomes и честный итог
Система SHALL сохранять для requested Secrets/SBOM/CVE отдельные `checked|unsupported|not_authorized|failed|skipped`, безопасные reasons, check/scanner versions и время; unrequested checks SHALL быть skipped, completed SHALL требовать все requested checked, partial — хотя бы один checked при неполноте, failed — ни одного checked, cancelled — отдельное terminal состояние.

#### Scenario: DB отказала после enqueue
- GIVEN Secrets/SBOM выполнены и checked, но CVE DB истекла либо CVE parse/timeout отказал
- WHEN публикуется terminal report
- THEN независимые результаты сохраняются, CVE failed без count и итог partial; exit 0 или пустой Results без required evidence не создают checked/0.

#### Scenario: Право отозвано
- GIVEN запрос был авторизован, но право на check отозвано до выполнения
- WHEN стадия должна начаться
- THEN запрещённый check не выполняется и получает not_authorized с безопасной причиной без раскрытия чужому субъекту; независимые outcomes сохраняются.

### Requirement: Честная OS и ecosystem граница
Система SHALL определять OS/ecosystem по проверяемому scanner evidence, не по tag suffix; доказанная неподдерживаемая ОС SHALL давать unsupported, malformed/unknown/missing required inventory — failed либо безопасный admission отказ, никогда checked/0; EOL сам по себе SHALL не доказывать отсутствие advisories.

#### Scenario: Debian и отсутствие npm
- GIVEN nginx target содержит неподдерживаемый Debian либо nginx Alpine proof не содержит npm dependency/advisory evidence
- WHEN формируется coverage
- THEN неподдерживаемый SBOM/OS CVE не имеет checked/count, валидный Secrets сохраняется; отсутствие npm inventory или наличие node executable не объявляется Node checked/acceptance.

### Requirement: TLS и ограниченная публичная авторизация registry
Система SHALL сохранять exact-host HTTPS/TLS verification, numeric-IP dial после all-answer public-IP DNS проверки каждого соединения, bounded redirects и anonymous Bearer с точными realm/service/repository pull scope без передачи токена чужому origin/CDN и без нового arbitrary egress.

#### Scenario: Hostile или недоступный Hub
- GIVEN private/mixed/rebound IPv4/IPv6 DNS, неверный TLS/realm/scope/port/redirect либо private/deleted/rate-limited target
- WHEN запрашиваются manifest/blob/token
- THEN запрещённые соединения блокируются, ошибки 401/403/404/429 безопасны, retry bounded, пользовательские registry credentials не запрашиваются; нет direct fallback, Docker socket, host/runtime/mounts или scanner DB fetch.

### Requirement: Численные пределы и очистка исполнения
Система SHALL использовать фиксированный Trivy 0.69.3/argv без shell/user flags, minimal env и до admission явно зафиксировать и enforce численные transport/aggregate download/manifest/layer count/compressed/unpacked/per-field/JSON-element/time/CPU/RAM/PID/scratch/decompression bounds с kill/cleanup, не повышая их автоматически ради candidate.

#### Scenario: N и N+1
- GIVEN policy фиксирует лимит N, а input/output достигает N либо N+1, включая malformed/truncated JSON, decompression и element limits
- WHEN стадия обрабатывает данные
- THEN N обрабатывается в policy, N+1 даёт bounded failure/cleanup без truncated checked, независимые успешные checks сохраняются; enforcement и cleanup имеют фактические boundary tests.

### Requirement: Свежая locally-attested DB
Система SHALL проверять local Ed25519 trust anchor, OCI/layer/extracted DB/metadata hashes, schema/freshness и timestamps при новом CVE admission и использовании, pin immutable DB release за CVE stage и сохранять фактические identity/hashes/times/checkedAt; локальная подпись SHALL обозначать локальное принятие байтов, не Aqua signature.

#### Scenario: Missing stale или tampered DB
- GIVEN DB отсутствует, просрочена, имеет неверные signature/key/hash/schema, symlink либо неправдоподобные timestamps/истёкший NextUpdate по legacy DB policy
- WHEN новый запрос требует CVE или принятый CVE stage начинает работу
- THEN новый запрос отклоняется без enqueue, worker-time отказ даёт CVE failed без нуля и не стирает независимые результаты; admission-time readiness не заменяет worker-time validation.

### Requirement: Unattended refresh и rollback
Система SHALL сохранять разрешённый host-only bounded HTTPS/GHCR→validation/conversion→local signing→immutable RO release flow с atomic activation/rollback без JWT/volume reset, private key в worker или прямого worker DB fetch.

#### Scenario: Ошибка выпуска или switch
- GIVEN candidate повреждён либо readiness/post-switch proof отказывает
- WHEN updater публикует или активирует release
- THEN candidate отвергается либо выполняется rollback, прежний release применим только пока свеж, running CVE не смешивает releases; controlled switch/no-op/unit simulation не считается реальной NEW upstream rotation.

### Requirement: Нормализация provenance и redaction
Система SHALL сохранять bounded stable finding_id в рамках target/category/CVE-or-rule/package/ecosystem/version/location, installed/fixed-or-unknown, severity sources, безопасный evidence_ref и все валидные provenance при identity-preserving dedup; raw secrets/stdout/stderr/credentials/unsafe URLs SHALL не попадать в SQLite/API/SSE/audit/log/UI/LLM.

#### Scenario: Два источника и canary
- GIVEN одна finding identity имеет два источника, другая имеет иной location, а недоверенные поля содержат secret-canary
- WHEN normalization/persist/report выполняются
- THEN первая сохраняет оба источника, другая остаётся отдельной, unknown fixed version не выдумывается, counts/pages соответствуют dedup и canary отсутствует во внешних каналах; fixture доказывает redaction, не remote-positive gate.

### Requirement: Forward-only долговечность и fencing
Система SHALL расширять ledger только forward-only migrations с сохранением PK/FK/index/events/outbox/ownership/idempotency, без reset и повышения legacy coverage/provenance, атомарно сохраняя independent outcomes/findings/SBOM/DB metadata/terminal event только текущей попыткой.

#### Scenario: Upgrade reopen restart и late worker
- GIVEN legacy secret/SBOM/CVE/partial/queued/running rows и stale worker после cancel либо новой lease
- WHEN migration/reopen выполняются повторно или terminal transaction отказывает
- THEN legacy данные сохраняются без invented provenance, late worker не перезаписывает результат, rollback/restart/API/SSE дают согласованный snapshot; backup/restore и retention проверяются.

### Requirement: Единая policy и честный browser UI
Интерфейс SHALL использовать единую серверную profile/readiness policy существующей формы/API, отличать discovery candidate от квалифицированной pinned identity, показывать independent coverage/DB provenance и сохранять paging/focus guarantees; новый универсальный capabilities endpoint не обязателен.

#### Scenario: Disabled профиль и owner reload
- GIVEN профиль выключен, tag лишь suggested или DB readiness изменилась
- WHEN пользователь выбирает найденный образ или отправляет новый запрос
- THEN UI объясняет границу и сохраняет выбор, сервер повторно проверяет admission; для принятого owner scan reload сохраняет pinned identity и различает checked zero, нет совпадений фильтра и не проверено.

### Requirement: Авторизация всех scan endpoints
Система SHALL проверять session/scan permission/origin/ownership/quota на POST/status/list/SSE/results/SBOM/cancel и сохранять закрытость internal JWT route извне без переноса локальной registration policy в публичное развёртывание.

#### Scenario: Anonymous revoked foreign subject origin или quota
- GIVEN запрос не авторизован, право отозвано, subject чужой, origin/CSRF неверны либо quota исчерпана
- WHEN вызывается scan endpoint
- THEN безопасный 401/403/404/429 не создаёт задания и не раскрывает чужие данные; SSE reconnect не даёт дополнительных полномочий.

## Non-goals
- Generic official/namespaced Hub admission, library/node/npm acceptance и Debian/Ubuntu не входили в прежний nginx-first инкремент; ниже они отдельно ограничены public-контрактом; single-target native evidence не является blanket acceptance. Distroless без подтверждённого OS inventory не получает checked OS CVE/SBOM. Windows, ARM, private credentials/registry, иные registry/platform, container/host/runtime/socket/mounts, LLM и публичный HTTPS deployment остаются вне этого public инкремента. Alpine baseline сохраняется; SBOM и ноль Secrets не доказывают отсутствие CVE.
- Отдельная test-only policy и тестовый CA для контролируемого proof не входят в поставляемую публичную политику; isolated operator proof не допускает bypass поставляемых guards.
- Full DIP-TASK-2 done не выводится из этой редакции. Датированные Node-positive и фактическая public upstream activation учитываются как отдельные scoped evidence, без объявления всех ecosystems/negative/sink матриц, controlled rollback, установленного scheduler или post-LLM refresh принятыми; исторические gates не являются круговым blocker уже поставленного bounded среза.

## Статус предложения и приёмка
Исторический nginx-first текст был подготовлен поверх DOC-1 v4 и хранится в текущем DOC-1 v5. Его прежняя формулировка «не applied spec» описывала тот authoring шаг, а не отсутствие текущей сохранённой версии. Настоящий полный кандидат основан на v5; фактические full-body MCP validation/propose/apply receipts, если получены, фиксируются отдельно в reconciliation manifest и не выводятся из наличия этого файла. Старые unapplied base-v1/base-v2 и discarded дельты не используются как implemented и не меняются. Feature-sourced предложение не закрывает strict task-level gate; для этой сверки source task — DIP-TASK-2, без объявления full DIP-TASK-2 done.

Перед rollout автор подтверждает текущие численные budgets и фиксирует недостающие aggregate/layer/unpacked/per-field пределы без выдуманных значений. Для legacy nginx-first решение совета требует сохранить или отдельно обосновать report caps: SBOM 2 000 000 bytes/1000 components, CVE 8 000 000 bytes/1000 findings/packages, Secrets 8 000 000 bytes; timeout ≤600 000 ms; worker 1 CPU/1 GiB/128 PID, scratch tmpfs 512 MiB; gateway 64 MiB/connection. Это требования handoff из совета, не новая проверка действующей конфигурации. Они не подменяют отдельный public resource envelope ниже: его 4 GiB worker/2304 MiB tmpfs не меняют legacy настройки и требуют собственного native подтверждения.

Применимая nginx gate-матрица: canonical/hostile target syntax; index/child/config bytes/hash/platform mismatch; tag mutation/idempotent replay/conflict; private/deleted/missing/rate-limited targets; TLS/realm/redirect/private/mixed/rebound DNS, gateway bypass/socket denied; malformed/truncated/oversized/unknown/unsupported inventory; missing/stale/tampered/signature/schema/symlink DB и expiry-after-enqueue partial; permissions/origin/quota; independent results/cancel/late lease/restart; canary; legacy migration/reopen/backup/restore. Фактические targeted/full relevant API tests/typecheck, UI focused tests/typecheck/build, gateway/isolation tests, real remote/browser proof и три review записываются автором; применимые gates без skips. Это историческая gate-запись до последующих Node-positive и public upstream activation receipts; их конкретная датированная область учитывается ниже, а непроверенные gates не переименовываются в PASS. При bounded blocker новый admission остаётся выключенным, handoff содержит точный partial и следующий доступный work, не arbitrary-images-ready.

Исторические authoring/qualification записи не являются повторными проверками 2026-10-20. Текущий reconciliation читает source и MCP и готовит полное тело; live DB/private state, protected8080 и Docker не открываются, source/task statuses не меняются. Разрешены только документные MCP validation/propose/apply по fresh policy после exact-base/delta checks; результат операции не предполагается заранее. Новые результаты validation фиксируются отдельно в reconciliation manifest.

## Общая долговечность отмены

### Requirement: Durable completed checks и original-claim fence всех image профилей
Система SHALL сохранять completed-check checkpoints до terminal публикации с привязкой к ledger-derived owner, полной pinned job, attempt, исходному random claim token, check/kind, commit time и integrity hash; публичный running report из checkpoint не создаётся. Checkpoint/final/retry требуют исходный caller token и running/current undelivered attempt с lease_until строго больше единственного captured clock; equality expired. Integrity SHA-256 обнаруживает несогласованные bytes, но не аутентифицирует враждебного DB administrator.

#### Scenario: Cancel побеждает, все checks сохранены или ни одного
- GIVEN owner scan queued/running имеет ноль, часть либо все requested completed checkpoints
- WHEN owner cancel выигрывает terminal transaction
- THEN eligible subset публикуется вместе с cancelled state, revoke token/outbox и одним cancelled event атомарно; даже all-checked subset не становится completed/partial. Requested без checkpoint остаётся absent/null/unknown без invented failure/count; реально completed failed/unsupported сохраняют outcome. Повтор cancel идемпотентен; если final completed выиграл первым, cancel конфликтует и completed не меняется.

#### Scenario: Reopen, expiry, replacement и storage failure
- GIVEN checkpoint committed до expiry, после чего процесс перезапущен или lease истекла, либо retry/replacement отозвали authority
- WHEN происходит cancel либо поздняя новая запись
- THEN expiry запрещает новые writes, но не стирает eligible historical subset текущего non-revoked claim; retry очищает checkpoints/token, replacement получает новый token/attempt, смешения attempts нет. Missing/wrong/revoked/expired caller token не пишет; cancellation publication fault откатывает весь terminal transaction, checkpoint write fault после sibling commit не фабрикует нормальный failed final и сохраняет recoverable evidence.

## Необязательный public-hub-amd64-v1

### Requirement: Public admission только отдельной composition
Система SHALL открывать public admission только отдельной серверной API/worker composition для явного канонического `registry-1.docker.io/library/name:tag`, `registry-1.docker.io/namespace/name:tag` либо соответствующего `@sha256:<64 lowercase hex>`, image-only/linux/amd64, без пользовательского profile/limits/bypass флага. Repository содержит ровно два lowercase компонента, каждый ≤128 символов, всего ≤255; URL, aliases, implicit registry, credentials, ports и nested paths не принимаются. `library/alpine` сохраняет legacy runners; explicit exact-nginx LOCAL/proof binding не заменяется public receipt.

#### Scenario: Generic target и закрытый default
- GIVEN допустимый namespaced Hub reference и отдельно выбранная public composition
- WHEN авторизованный субъект заказывает поддерживаемые checks
- THEN API выполняет реальную eligibility/identity inspection без nginx execution binding; тот же reference не открывает default/legacy admission, а произвольный stored executionProfile не даёт worker полномочий.

#### Scenario: Readiness изменилась и повтор
- GIVEN права/origin/quota допустимы, но worker/gateway недоступен до либо после inspection или для vuln нет аутентифицированной пригодной DB
- WHEN поступает новый запрос
- THEN enqueue/202 отсутствуют; точный ранее принятый subject/idempotency replay возвращает прежний scanId до повторной resolution/readiness, конфликт параметров не создаёт второй scan.

### Requirement: Public acquisition сохраняет реальную identity
Система SHALL получать public image только registry-only через прежний bounded HTTPS/DNS/TLS/realm/redirect gateway, проверяя index/единственный linux/amd64 child manifest/config до enqueue и заново проверяя pinned metadata при acquisition, затем compressed size/hash, expanded diffIDs и archive hash без подстановки Alpine/nginx identity. Receipt содержит ровно registry/repository/digest/configDigest/platform, ordered layerDigests/diffIds, archiveSha256 и версии `public-hub-amd64-v1`, `public-hub-resources-v1`, `trivy-0.69.3-public-archive-v1`; имя профиля само по себе не является evidence.

#### Scenario: Tag drift и повреждённый слой
- GIVEN tag закреплён за child A/config C, а после enqueue указывает на B
- WHEN worker получает pinned A и проверяет слои
- THEN результат остаётся A/C/linux/amd64; mismatch hashes/size/diffIDs/config/platform, неоднозначный child или чужой scanner identity дают bounded отказ без checked чужих байтов.

#### Scenario: Недопустимый archive или сетевой обход
- GIVEN foreign/inline/zstd/uncompressed layer, artifact manifest, concatenated/truncated gzip, CRC/ISIZE/tar mismatch, escaping regular path/hardlink или competing same-field GNU/PAX override
- WHEN acquisition валидирует input
- THEN input отклоняется без host extraction/исполнения entrypoint; image symlink не разрешается на хосте, cleanup удаляет только scratch своей попытки. Запрещённые realm/DNS/redirect, приватный/удалённый/rate-limited Hub не открывают direct fallback или передачу Bearer CDN; scope остаётся `repository:<real repository>:pull`.

### Requirement: Фиксированные public acquisition budgets
Система SHALL ограничивать public acquisition неизменяемой `public-hub-resources-v1`, не принимая caller limits и не расширяя legacy ceilings. MiB = 1024² bytes; пределы одной попытки:

| Ресурс | Public предел |
| --- | ---: |
| Ordered layers | 1–64 |
| Compressed layer / aggregate | 128 / 512 MiB |
| Delivered HTTP response-body bytes | 544 MiB |
| Transport/GET attempts | 320 |
| Acquisition deadline | 180 000 ms |
| Expanded layer / aggregate, включая tar padding | 512 / 1024 MiB |
| Entries / regular-file payload | 100 000 / 256 MiB |
| Extension payload / effective path-link-PAX field | 64 KiB / 512 bytes |
| Aggregate PAX records | 1024 |
| Docker-save archive / logical scratch | 1152 / 2048 MiB |
| Metadata-only object / config | 4 000 000 / 1 000 000 bytes |
| Inspection index descriptors / logical objects | 1024 / 3 |
| Inspection delivered bodies / attempts / deadline | 16 000 000 bytes / 12 / 30 000 ms |

#### Scenario: N+1 и точный смысл metrics
- GIVEN descriptor, поток, распаковка, tar field, entry count или cumulative budget превышает соответствующий N
- WHEN inspection/acquisition обрабатывает N+1
- THEN sticky bounded failure и own cleanup не дают truncated checked. Совместимые имена `wireBytes`/`inspectionWireBytes` обозначают доставленные transport response bodies (включая auth/error/redirect), не физический wire: headers, framing, CONNECT и TLS/TCP overhead исключены; rejected gateway chunk до sink не учтён. `requests` считает gatewayGet attempts, включая auth/redirect и неуспешный CONNECT attempt, но не отдельный CONNECT плюс GET. Logical scratch с 16 MiB filesystem headroom не объявляется allocated blocks/RSS/global quota.

### Requirement: Отдельный public worker resource envelope
Система SHALL запускать public worker только с Trivy 0.69.3, fixed argv/minimal env без shell/user options, cgroup-v2 memory ровно 4 GiB, swap 0, CPU 1, PIDs 128 и реальным non-symlink tmpfs `/tmp/trivy` ёмкостью от 2048+16 до 2304 MiB; startup/heartbeat/consume повторно проверяют envelope. Stage timeout ≤120 000 ms, archive attempt ≤600 000 ms, scanner output caps Secrets 1 000 000, CycloneDX 2 000 000, CVE 8 000 000 bytes; нормализация ≤1000 components/packages/results/findings.

#### Scenario: Нет физического quota либо scanner превысил cap
- GIVEN неверный cgroup/tmpfs или превышение stage/output/scratch bound
- WHEN public worker стартует либо выполняет check
- THEN готовность не выдаётся или выполнение прерывается с kill/cleanup без fabricated checked; ранее принятые checkpoints сохраняются по отдельному fencing-контракту. Logical audits не заменяют физический tmpfs/cgroup и не доказывают отсутствие OOM или суммарную ёмкость Docker VM; старый 1 GiB LOCAL worker не расширяется.

### Requirement: Public SBOM только из подтверждённого inventory
Система SHALL нормализовать public CycloneDX только после receipt/config/diffID identity проверки, с фактическими OS components и PURL/name/version/distro/architecture evidence в закрытый набор `apk,deb,rpm,npm,pypi,gem,gomod,cargo,maven,composer,nuget`. Допустимы OS families `alpine,debian,ubuntu,redhat,centos,rocky,alma,oracle,amazon` с numeric release из 1–4 компонентов длиной ≤80; это parser support, не blanket native qualification. Нормализованный SBOM не заменяет CVE.

#### Scenario: Debian с языковыми компонентами и malformed PURL
- GIVEN receipt-backed Debian 12 inventory с deb/npm либо другими перечисленными ecosystems
- WHEN scanner identity и component evidence проходят проверку
- THEN owner получает bounded pageable normalized inventory; неизвестные ecosystem/component type/qualifiers, mismatch PURL/version/distro/config/diffID или неполный required inventory дают failed SBOM без проверенного пустого списка. Maven `group:artifact`, Go module, scoped npm, Composer `vendor/package`, NuGet case и bounded версии сохраняются только при валидной нормализации.

### Requirement: Public CVE не выдумывает OS и Node coverage
Система SHALL давать checked public vuln только после валидных известных result class/type, положительного OS inventory и соответствия каждой finding установленному package/version. Node checked требует положительного валидированного npm inventory; его отсутствие в report означает unsupported `NODE_INVENTORY_UNKNOWN`, не доказанное отсутствие Node и не skipped/checked zero. `vuln` — один requested check, а OS/Node — его coverage details: checked vuln с unknown Node не превращает Node в checked и сам по себе не требует partial scan. Omitted/false EOSL не является гарантией lifecycle support.

#### Scenario: Unknown, EOL и malformed inventory
- GIVEN OS evidence отсутствует/неизвестно либо известная ОС имеет EOSL:true либо package/result evidence malformed
- WHEN public CVE stage проверяет scanner bytes
- THEN отсутствующее/нераспознаваемое OS evidence даёт unsupported OS_UNKNOWN и unknown Node; известная OS проходит inventory parser, после чего EOSL:true даёт unsupported OS_EOL и unknown Node; пустой Results, missing/invalid required packages, неподдержанный analyzer/source или mismatched installed version дают failed, не silently omitted findings и не checked/0. Secrets/SBOM сохраняют собственные outcomes; Java DB/network fallback не разрешается.

#### Scenario: Checked OS и неизвестный Node
- GIVEN проверен deb inventory и vuln checked, но npm inventory не доказан
- WHEN owner читает completed report
- THEN OS checked и Node unsupported/NODE_INVENTORY_UNKNOWN показаны независимо; completed описывает requested checks, не универсальную полноту ecosystem coverage.

### Requirement: Public config использует собственную pinned authority
Система SHALL выполнять optional `config` только при явной public composition и исходной действующей owner/job/attempt/token/check authority, загружая pinned manifest/config через прежний gateway с проверкой hashes/types/length/platform до и после load; выключенный config не читает loader. Лимиты: manifest/config по 1 000 000 bytes, verifier total 2 000 000 bytes, cumulative load 30 000 ms, ≤8 requests. Generic checked Secrets/SBOM/CVE не публикуются через legacy non-archive fallback.

#### Scenario: Config-only и утраченный claim
- GIVEN public config-only job либо config вместе с archive checks
- WHEN load завершается штатно либо после cancel/retry/replacement/lease expiry
- THEN только действующий исходный claim получает sanitized config checkpoint/result для своей manifest/platform; late/uncooperative bytes отбрасываются, environment/command/raw config не выходят в ledger/API/UI. Generic target не переписывается в legacy admitted repository.

### Requirement: Public checkpoints и финал не противоречат evidence
Система SHALL проверять оригинальные normalized envelopes, receipt/job/requested checks, owner, attempt/token, lease, evidence hash и DB policy перед transactional checkpoint/final/read, сохраняя accepted snapshots при reopen и не позволяя финалу стереть либо изменить accepted Secrets/SBOM/config. Final receipt/scanner и CVE identity/findings/DB/advisory согласуются с accepted checkpoints; допустимы только действующая DB-policy reevaluation и уже ограниченный advisory report-budget omission, не произвольная подмена.

#### Scenario: Scratch audit после принятой Secrets
- GIVEN Secrets audited и checkpoint принят, затем поздний scratch audit/deadline/abort отказал
- WHEN runner/consumer завершает попытку
- THEN interruption/storage error распространяется без нормального fabricated failed final и без fallback стирания siblings; cleanup выполняется, claim/checkpoints остаются для существующего cancel/recovery lifecycle. Поздний валидно выглядящий SBOM без принятого checkpoint не публикуется.

#### Scenario: Противоречивый final и реальная DB expiry
- GIVEN final меняет receipt/findings/outcome уже принятого check либо заявляет DB_UNAVAILABLE
- WHEN ledger выполняет fenced final transaction
- THEN противоречие откатывает все publication/state/event writes; лишь независимо доказанная непригодность DB самого accepted CVE checkpoint в captured final time может дать CVE failed/DB_UNAVAILABLE, не стерев Secrets/SBOM. Reason string или иная replacement DB не доказывают expiry; wrong/missing/expired/revoked token не пишет ничего.

### Requirement: Отмена public scan сохраняет cancelled и принятый subset
Система SHALL при owner cancel прекращать новые стадии и отзывать полномочия текущей попытки, публикуя лишь её ранее принятые валидные checkpoints с terminal `cancelled`, даже если часть checks checked; отмена не превращается в completed или автоматический partial final. Lease expiry запрещает новые writes, но само по себе не удаляет принятый recoverable subset; retry/replacement явно отзывают прежнюю authority.

#### Scenario: Cancel после expiry и reopen
- GIVEN текущая попытка имеет durable accepted Secrets/SBOM/config subset, процесс перезапущен либо её lease истекла без replacement
- WHEN владелец отменяет scan
- THEN после повторной валидации evidence доступен только принятый subset, state cancelled; незавершённые requested checks имеют безопасную причину неполноты, unrequested остаются skipped, late final не меняет state. Чужой owner не читает и не отменяет, retention удаляет доступ согласно прежней политике; historical DB evidence читается по accepted evaluation, не сегодняшней freshness.

### Requirement: Public DB trust и usability не равны readiness
Система SHALL для нового public vuln admission закреплять аутентифицированный immutable signed DB release и policy `cve-db-updated-at-14d-v2`, проверяя Ed25519 anchor/hashes/source/schema/timestamps при admission, worker pre/postflight и final fence; boolean ready, смонтированный каталог или локальная подпись не заменяют эти проверки и не являются Aqua signature. Production anchor остаётся default; явная public LOCAL composition API и worker может использовать одинаковый проверенный SPKI fingerprint и bounded RO Ed25519 public PEM, invalid present fingerprint не даёт fallback, private key не монтируется.

#### Scenario: NextUpdate пересечён либо DB действительно истекла
- GIVEN current-policy DB имеет допустимые signature/schema/hash/calendar/order, future skew ≤300 s, NextUpdate после UpdatedAt не далее 7 суток
- WHEN age от UpdatedAt достигает ровно 14 суток либо превышает их
- THEN equality ещё usable, превышение даёт отказ нового CVE admission или DB_UNAVAILABLE stage/final; age >24 h и now≥NextUpdate показываются как warnings/stale-but-usable, не как новая подпись или омоложение по DownloadedAt. Это действующая v2 policy, не ослабление frozen legacy policy; tampering/missing/untrusted DB всегда закрывают CVE, non-CVE checks независимы.

### Requirement: Public owner report и UI выбирают contract по evidence
Система SHALL сохранять прежние session/permission/origin/CSRF/quota/owner guards на create/eligibility/list/status/SSE/results/SBOM/report/cancel и выдавать bounded normalized public SBOM/CVE marker только по полному валидному persisted public receipt в одном read snapshot с payload. Endpoint либо repository не повышают legacy evidence; queued/config-only generic status marker описывает pinned target, не checked coverage. Raw secrets/stdout/stderr/paths/credentials/unsafe URLs не сохраняются и не выдаются.

#### Scenario: Public endpoint читает legacy edge
- GIVEN legacy Alpine/exact-nginx SBOM release `edge` и иной настоящий receipt-backed public numeric report
- WHEN owner читает ordinary/report-v1 и reload в browser
- THEN legacy остаётся unmarked с прежней grammar, public сохраняет закрытый public contract; pinned full reference берётся owner-scoped без history walk/tag cache. Чужой owner получает 404, anonymous 401 без rows; public nonnumeric checked release не становится допустимым через legacy route.

#### Scenario: Discovery и смена выбранных checks
- GIVEN поиск предлагает Hub candidate со `scannable:false`, либо target/checks/consent изменены
- WHEN пользователь подтверждает новый запуск
- THEN UI делает свежую preflight eligibility и API повторяет guards/inspection; pending submission инвалидируется при изменениях. Owner report сохраняет paging/filter/focus/reload guarantees и различает checked zero, no filter matches и unknown/не проверено; профиль не обещает проверку всех ecosystems конкретного образа.

### Requirement: Новый public stand не мигрирует LOCAL8080
Система SHALL предоставлять public qualification только отдельным opt-in стендом `dip-public-images` на `127.0.0.1:8081`, со своими accounts/ledger volumes, сетями, stable JWT issuer/audience `dip-public-images` и private state `.local-public-images`; первый запуск требует явного признания isolated/new data. Существующий LOCAL8080 не активируется, не импортируется, не мигрирует и не теряет JWT/accounts/reports; legacy activation block сохраняется.

#### Scenario: Первый запуск и собственный restart
- GIVEN оба root ignore файла защищают новую private state после negations, отсутствуют Dockerfile-specific ignore overrides, выполнен независимый review и выбран доверенный local Unix Docker endpoint
- WHEN coordinator явно запускает новый стенд и затем его stop/relaunch
- THEN создаются только свои защищённые state/JWT/volumes без чтения старого JWT/private signing key; последующий запуск сохраняет собственные accounts/reports/pins. Proof использует новый browser context: cookies не изолированы TCP-портом, старая 8080 session не является evidence изоляции.

#### Scenario: Unsafe image или неопределённый Docker outcome
- GIVEN image defaults/env/hooks, mounts/resources/network/ownership не соответствуют независимой fixed policy, namespace collision или Docker timeout/postflight uncertainty
- WHEN launcher оценивает build/start/stop
- THEN fail-closed inspection не принимает чужие ресурсы, service start возможен только после image-policy проверки по immutable IDs без build/pull при start; literal endpoint закреплён на операцию. Свой durable lock/mutation receipt остаётся HOLD при неопределённости, без auto-retry/reset/unlock/volume deletion/secret rotation; client timeout не означает отмену daemon work. Нет socket/privileged/host-network/private-key mount или API/worker host ports.

### Requirement: Public stand не наследует LOCAL refresh authority
Система SHALL фиксировать public stand CVE disabled при отсутствии public activation на первом up либо собственные public release/PEM pins при валидной activation, отказывая при invalid activation; последующий up использует свои pins, а не текущий LOCAL activation. Прежние LOCAL updater/scheduler/manual refresh команды не управляют этим стендом; public layout validation не утверждает signature/freshness readiness. Отдельный public provisioning/refresh использует public-owned assets и dedicated future signer без чтения старого private key; preparation не меняет active binding и не переподписывает прежние signed bytes. Migration, activation и установка scheduler требуют явной отдельной операции, не происходят автоматически при up.

#### Scenario: LOCAL activation сменился или pinned DB устарела
- GIVEN public stand уже имеет stable own profile и неизменённый JWT
- WHEN LOCAL activation меняется либо собственный pinned DB становится непригодным
- THEN profile/release не переключается молча и DB не переиздаётся для омоложения; CVE admission безопасно закрывается, собственные accounts/reports остаются. Поставленный отдельный public refresh проходит shared-lock/public-binding/preservation workflow, не обходит legacy guards и не допускает ручной подмены pins.

#### Scenario: Public preparation и guarded migration
- GIVEN public v1 профиль закрепляет прежние signed assets и public PEM, а public-owned preparation проверена
- WHEN оператор явно выполняет preparation и затем отдельную v1→v2 migration
- THEN preparation копирует проверенные signed bytes без resign и active switch; migration сохраняет собственные JWT/accounts/reports и активирует тот же bundle под guarded maintenance. Dedicated future signer не импортирует прежний private key; invalid/mismatched state не генерирует молча замену. LOCAL8080 не читается и не мигрирует.

#### Scenario: Manual refresh, preservation и scheduling
- GIVEN проверен fresh immutable upstream candidate для собственного public v2 binding, нет другой операции/HOLD и выполнены capacity/retention prechecks
- WHEN явно запускается public activation либо отдельно установленный scheduler вызывает тот же workflow
- THEN shared lock, fence/drain и проверенные snapshots защищают собственные stores; API/worker replacement не меняет JWT/accounts/reports, а при persisted LLM descriptor также history/quota и optional API-only key mount. Web открывается последним после final typed comparison; stopped stack не запускается scheduler-ом. Неопределённый side effect сохраняет HOLD без auto-retry/unlock/reset/prune; simulation/no-op не доказывает actual rotation/rollback или установленное расписание.

### Requirement: Public SOURCE evidence не заменяет native и rollout gates
Система SHALL сохранять production public opt-in закрытым до применимых реальных pinned-image/Trivy/DB/browser/security/resource negative gates без skips и трёх независимых security/correctness/spec reviews; source review, normalized fixture и успешный launcher не являются native acceptance. Initial CVE opt-in сохраняет требование реального positive CVE с package/installed/fixed-or-unknown/severity source/provenance; последующий валидный checked zero не фабрикуется. Full task done, Node-positive и NEW upstream rotation требуют собственного evidence.

#### Scenario: Контролируемые проверки зелёные, native не выполнен
- GIVEN OCI и worker/ledger/API scoped reviews закрыли свои finding, а controlled HTTP/SQLite/Chromium показали owner reports
- WHEN coordinator оценивает готовность public rollout
- THEN статус остаётся SOURCE implemented/controlled-test reviewed, не native/live/deployed PASS; отдельно подтверждаются настоящий registry archive и raw Trivy compatibility для заявленного покрытия, signed DB operational readiness, физические cgroup/tmpfs/RO mounts, TLS/egress/no-socket, owner/origin/cancel/restart/canary и legacy regression. Launcher remediation дополнительно требует независимого re-review до launch; неизвестные base-image defaults/Engine behavior не обходят guards.

### Requirement: Debian TEMP сохраняет source identifier и честный partition
Система SHALL принимать помимо CVE только `TEMP-[0-9]{7}-[A-F0-9]{6}` из public Debian OS/deb evidence, сохраняя исходный identifier в identity и существующем поле cveId без подмены CVE. Legacy intake остаётся CVE-only. Весь checked public vuln dataset SHALL иметь identifierCounts.cve и identifierCounts.debianTemp с суммой findingCount; page/filter counts не подменяют этот partition.

#### Scenario: TEMP, dedup и запрет выдуманных ссылок
- GIVEN Debian inventory содержит CVE и валидный TEMP либо иной namespace/невалидный TEMP
- WHEN normalizer, durable validation и owner HTTP/browser обрабатывают report
- THEN CVE и TEMP учитываются отдельно при одном стабильном ID каждой identity; invalid identifier даёт fail-closed, не silently dropped row. TEMP имеет пустые advisory references, не CVE.org/NVD/FIRST/БДУ mapping; raw identifier fields, чужие ecosystems и legacy TEMP не принимаются. Дубликаты сохраняют bounded source assessments/provenance; разные package/version/location не сливаются.

## Public evidence и оставшиеся gates — сверка 2026-10-21
- Текущие source contracts: public-image-policy/evidence, archive-result-contract, archive-scan-worker, outbox-consumer, ledger checkpoint/final/cancel, PublicImageScansService, strict browser report parsers. Точные SHA-256 и evidence attribution находятся в `docs/public-spec-reconciliation-20261020.md`.
- `docs/public-image-final-20261018.md` и безопасный Node receipt документируют два native targets: Debian 12.15 — 241 vulnerabilities (236 CVE + 5 TEMP), Node 22.14.0/Alpine3.21 — 158 CVE, npm inventory 200. Node single-target native evidence прочитано; Debian полный JSON не восстанавливается из обрезанного output. Это исторические counts, не golden values следующего scan.
- Полная negative/OS/ecosystem/sink/resource/cancel/restart/production матрица не выводится из двух targets. Source tests, controlled HTTP/Chromium, actual native и operational rollout evidence остаются разными классами. Старые «native NOT_RUN» и launcher HOLD описывают предыдущие этапы, не опровержение более позднего датированного proof; текущая live доступность не проверялась.
- По датированному `docs/public-product-handoff-20261021.md` public prepare, guarded v1→v2 migration и fresh upstream stage+actual guarded activation выполнены с сохранением accounts/reports/JWT. Default CLI уже использует concrete shared-lock/snapshot bridge; прежнее «unwired» superseded. Это maintenance evidence автора, не новый scanner/browser proof этой сверки. Scheduler не установлен/не native-qualified, post-LLM refresh/preservation не выполнялся; поддержка четырёх stores в source/tests не заменяет такой запуск. Controlled rollback отдельно не принят.
- Positive native Secrets packet `public-secrets-qualification-20261020.dedup.json`: 4 actual native invocations, по 2 never-issued canary findings; 61 named checks и 4 JSDOM tests. Duplicate derivative — harness mutation 4→2 rows с ID первого исходного вхождения, не native Trivy duplicate-output claim. IDs report-local positional, не reorder-stable/global identity. Temporary SQLite/owner HTTP/SSE/reopen/retention проверены в scoped harness, не production browser/provider/LLM/preinvoke verifiedArchive qualification; подробные hashes/атрибуция в reconciliation manifest.
- Эта редакция не применение старого mixed target, не task closure и не изменение protected8080/private state. Source DIP-TASK-2; реальные MCP revision IDs/versions фиксируются только по ответам сервера в manifest. По сообщению владельца от 2026-10-21 hash70e1… — осознанный mount-order normalization fix с independent reviewer GO/29 targeted PASS; единственный actual continuation завершился новым HOLD phase=initialize/exit1. Это датированное owner evidence, не неизвестный source drift, не выполненная post-LLM qualification и не постоянное product behaviour; нового continuation эта сверка не выполняет и не разрешает.
