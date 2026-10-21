# P0: авторизованный registry image scan и достоверный отчёт

## Purpose
Предложить целевой первый bounded image-only срез для найденного публичного `library/nginx` на Alpine/linux/amd64 с сохранением существующего `library/alpine` baseline и требований DIP-DOC-1 v4. Это полный целевой контракт по решению 5033a59a-853c-4bb5-80b2-fbaefd06f3fd, не applied spec, implemented claim или remote PASS. Независимые Secrets/SBOM/CVE не означают поддержку произвольных Docker Hub images, всех ОС или Node dependencies; применять описание доступного поведения можно только после реализации и приёмки соответствующего среза.

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
- GIVEN DB отсутствует, просрочена, имеет неверные signature/key/hash/schema, symlink либо неправдоподобные timestamps/истёкший NextUpdate
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
- Generic official/namespaced Hub admission, library/node/npm acceptance, Debian/Ubuntu/distroless/Windows, private credentials, иные registry/platform, container/host/runtime/socket/mounts, LLM и публичный HTTPS deployment не входят в этот инкремент. Alpine baseline сохраняется; SBOM и ноль Secrets не доказывают отсутствие CVE.
- Отдельная test-only policy и тестовый CA для контролируемого proof не входят в поставляемую публичную политику; isolated operator proof не допускает bypass поставляемых guards.
- Full DIP-TASK-2 done, remote Node-positive и реальная NEW upstream DB rotation не объявляются без отдельного evidence. Полезный nginx OS срез может быть partial инкрементом; будущие Node/upstream критерии отдельно pending, не PASS и не круговой blocker первого backend среза.

## Статус предложения и приёмка
Дельта подготовлена поверх DOC-1 v4 и не применяется этим шагом. Старые unapplied base-v1/base-v2 и discarded дельты не используются как implemented и не меняются. Feature-sourced предложение не закрывает strict task-level gate; будущая task-sourced полная дельта описывает только принятое фактическое поведение.

Перед rollout автор подтверждает текущие численные budgets и фиксирует недостающие aggregate/layer/unpacked/per-field пределы без выдуманных значений. Решение совета требует сохранить или отдельно обосновать report caps: SBOM 2 000 000 bytes/1000 components, CVE 8 000 000 bytes/1000 findings/packages, Secrets 8 000 000 bytes; timeout ≤600 000 ms; worker 1 CPU/1 GiB/128 PID, scratch tmpfs 512 MiB; gateway 64 MiB/connection. Это требования handoff из совета, не новая проверка действующей конфигурации.

Применимая nginx gate-матрица: canonical/hostile target syntax; index/child/config bytes/hash/platform mismatch; tag mutation/idempotent replay/conflict; private/deleted/missing/rate-limited targets; TLS/realm/redirect/private/mixed/rebound DNS, gateway bypass/socket denied; malformed/truncated/oversized/unknown/unsupported inventory; missing/stale/tampered/signature/schema/symlink DB и expiry-after-enqueue partial; permissions/origin/quota; independent results/cancel/late lease/restart; canary; legacy migration/reopen/backup/restore. Фактические targeted/full relevant API tests/typecheck, UI focused tests/typecheck/build, gateway/isolation tests, real remote/browser proof и три review записываются автором; применимые gates без skips. Future Node/new upstream event фиксируются отдельно unverified, не PASS. При bounded blocker новый admission остаётся выключенным, handoff содержит точный partial и следующий доступный work, не arbitrary-images-ready.

В этом spec-author шаге scanner/network/browser/tests не выполнялись, реальный nginx digest/CVE и свежесть живой DB не подтверждены; код, четыре foreign notices и task statuses не изменяются.
