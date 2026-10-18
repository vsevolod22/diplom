# Public image-only на 8081 — как пользоваться

**Статус на 18 октября 2026, после 14:06 UTC:** отдельный локальный стенд **http://127.0.0.1:8081 работает**. Настоящие native browser/API/UI проверки Debian и Node завершились PASS. Это готовность указанного ограниченного локального сценария, **не обещание проверки буквально любого образа и не полная production-приёмка**.

Координатор завершил guarded recovery/redeploy с проверенными quiescent SQLite backups и сохранением аккаунтов, истории, JWT и volumes public-стенда. Исходный public HOLD архивирован. **Существующий 8080 не изменён, HTTP 200 подтверждён; это отдельный legacy-профиль.** Его данные не импортируются в 8081. Для использования уже работающего UI не надо повторять launcher, recovery, пересоздание или очистку volumes.

## 1. Откройте отдельную сессию и зарегистрируйтесь

1. Используйте отдельный профиль браузера либо **выделенный incognito/private context только для 8081**. Не открывайте в нём авторизованный 8080. Cookies привязаны к hostname/path, а не порту; несколько incognito-окон одного браузера также могут делить context.
2. Откройте **http://127.0.0.1:8081/register** — именно `127.0.0.1`, не `localhost`, `8080` или dev-порт `5173`.
3. Создайте **новый локальный аккаунт** со своим email и паролем не короче 12 символов. Не используйте чужие тестовые учётные данные; не передавайте пароль, cookie или JWT в чат/логи.
4. После регистрации откройте **http://127.0.0.1:8081/scans/new**. При последующем входе используйте `/login` на том же 8081 и свой аккаунт. Старый аккаунт с 8080 автоматически не переносится.

Страницы `/demo/scans` содержат вымышленные данные и не запускают native scanner. Для реальной проверки нужны `/scans/new` и `/scans`.

## 2. Введите canonical reference вручную

В поле **Canonical reference Docker Hub** можно ввести один из двух реально проверенных targets:

```text
registry-1.docker.io/library/debian:bookworm-slim
registry-1.docker.io/library/node:22.14.0-alpine3.21
```

Общий допустимый вид — публичный official образ `registry-1.docker.io/library/name:tag` либо публичный namespaced образ `registry-1.docker.io/namespace/name:tag`; поддерживается и явный `@sha256:…`. Это синтаксис кандидата, не гарантия успешного сканирования. Нужны canonical registry, namespace и selector; сокращения вроде `node:22`, alias `docker.io`, URL с `https://`, credentials, произвольный порт, вложенные repository paths и другой registry этим профилем не разрешаются.

Не обязательно выбирать поисковую подсказку. Поиск показывает кандидатов и **не разрешает запуск**; действительный manifest/config, публичность, platform, resource bounds, worker readiness и DB проверяет сервер.

## 3. Выберите проверки, подтвердите цель и отправьте один запуск

1. Отметьте **Secrets**, **SBOM**, **CVE** и **Image config**. Название CVE в форме соответствует запросу `vuln`; public-отчёт честно разделяет CVE и Debian TEMP advisories.
2. Дождитесь актуального серверного допуска для этой ссылки и выбранных checks. Изменение цели/проверок требует повторной проверки и нового подтверждения.
3. Подтвердите выбранную цель/область и нажмите **«Запустить скан»**. UI выполняет свежую eligibility-проверку перед POST; предыдущая зелёная подсказка не является бессрочным разрешением.
4. Дождитесь страницы задания. **POST 202 — только квитанция**, не завершение и не доказательство digest/platform. Закреплённая цель подтверждается авторизованным GET status; дальнейший отчёт относится именно к ней, а не к предполагаемому содержимому tag.
5. При задержке или потерянном ответе сначала проверьте **http://127.0.0.1:8081/scans**. Не создавайте повторные сканы вслепую. Отказ eligibility/DB/resource guard — не повод менять pins, отключать guards или подставлять другую identity.

Оба успешных native proof заняли около минуты с небольшим, но это **не SLA**: новый target, registry, размер, очередь и DB могут дать иной срок или отказ. Условия выполнения ограничены; EOL/unknown/unsupported/failed не превращаются в checked/0.

## 4. Прочитайте отчёт и проверьте сохранность

- **Secrets:** 0 означает ноль находок в выполненной поддерживаемой области, а не доказанное отсутствие всех секретов.
- **SBOM:** инвентарь пакетов, не список CVE и не гарантия полного покрытия всех языков. Используйте серверные ecosystem/name filters и pagination; loaded page не равна всему inventory.
- **Уязвимости:** смотрите общее число и namespace-разделение. **241 всего = 236 CVE + 5 Debian advisories**, не «241 CVE». TEMP-карточка помечена **«Debian advisory (не CVE)»**, сохраняет точный `TEMP-…` ID и не получает выдуманных CVE.org/NVD/БДУ ссылок. Whole-report counts до фильтров, matched filter count и текущая страница имеют разные области.
- **Node/npm:** `NODE_INVENTORY_UNKNOWN` означает неизвестный inventory, **не доказанное отсутствие** Node/npm. Debian не обязан иметь npm-пакеты или положительное npm coverage.
- **Image config:** проверяется только поддерживаемая OCI User metadata. Одна находка не означает один реально исполненный exploit; checked без находки не доказывает non-root runtime. Dockerfile, History/IaC и running container этим результатом не проверены.
- Reload страницы и повторный вход своим аккаунтом на 8081 должны оставлять доступ к своим сохранённым отчётам. Просматривайте `/scans` под тем же владельцем; не передавайте session cookie для чужого доступа.

Checked — факт выполненной проверки в указанной области, **не вердикт «образ безопасен»**.

## Фактические результаты 18.10.2026

| Target | Native scan ID | UTC: начало → конец | Результаты |
| --- | --- | --- | --- |
| Debian `bookworm-slim` | `b2c8f335-f1e8-4c0e-be33-561bd0cda1a6` | 14:03:09.760Z → 14:04:25.768Z | completed; все 4 checked; Secrets **0**, SBOM **88**, Debian **12.15**, уязвимости **241 = 236 CVE + 5 TEMP**, config **1** |
| Node `22.14.0-alpine3.21` | `4dfdcc89-c78f-415f-b73b-74cde4798a4d` | 14:05:06.605Z → 14:06:18.591Z | completed; все 4 checked; Secrets **0**, SBOM **217**, в том числе npm **200**, Alpine **3.21.3**, уязвимости **158 CVE + 0 TEMP**, config **1** |

Эти два proof выполнены координатором на восстановленном стенде: manual entry/checks/consent → fresh eligibility → POST → native worker → проверка report/identity/DB/counts/UI → reload → fresh own login. Это не synthetic scanner fixtures и не подмена HTTP. Tag может измениться, база — устареть; числа будущего запуска могут отличаться.

**Граница evidence:** [полный безопасный Node receipt](public-image-node-native-20261018.json) сохранён: `PASS_SINGLE_NATIVE_TARGET`, native execution true, 0 page errors/external browser requests, без HTTP/OCI/scanner injection; browser cleanup подтверждён. Его pinned digest — `sha256:01393fe5a51489b63da0ab51aa8e0a7ff9990132917cf20cfc3d46f5e36c0e48`. Debian PASS/время/scan ID/OS/итоги получены координатором из настоящего запуска; полный stdout Debian-квитанции не сохранён. Дополнительно [read-only агрегаты обоих сохранённых отчётов](public-image-native-ledger-20261018.json) независимо подтверждают Debian **236 CVE + 5 TEMP**, Node **97 APK CVE + 61 npm CVE**, все четыре checked, полный SBOM и исторические DB fingerprints. Это чтение именно этих persisted reports, не подстановка replay/Node evidence вместо Debian. Commit times ledger — 14:04:17 и 14:06:09 UTC, не finish times browser harness.

## Границы профиля и ресурсы

`public-hub-amd64-v1` / `public-hub-resources-v1` — отдельная image-only composition:

- **Только публичный Docker Hub**, official/namespaced repository, **linux/amd64**, поддерживаемые manifest/layer formats. Это не private registries, GHCR, ARM64, Windows или любой произвольный registry.
- Worker: **4 GiB RAM**, total memory+swap тоже 4 GiB — **без дополнительного swap**, CPU **1**, PIDs **128**, scanner tmpfs **2304 MiB**. Учитывайте эту память в Docker Desktop; это не безлимитная очередь/ресурсный сервис.
- До **64 layers**, до **128 MiB** на сжатый layer / **512 MiB** суммарно, до **1 GiB** expanded total и **2 GiB logical scratch**. Manifest/config, archive, file/entry/report sizes, requests и время также ограничены. Scratch/tmpfs/RAM — разные бюджеты, не взаимозаменяемые разрешения на любой размер.
- Entry point исследуемого образа не запускается, worker не получает Docker socket. Результат статического image scan не квалифицирует host/runtime capture.
- Реально проверены **два названных target**, а не все OS/ecosystems/negative cases. Наличие в коде закрытого списка экосистем не равно native certification каждой из них. Runtime/host/LLM отдельно не включаются этим профилем.

## Закреплённая DB: usable, но не свежая и без автообновления

Сохранённая Node-квитанция фиксирует:

| Поле | Значение |
| --- | --- |
| UpdatedAt | `2026-10-16T01:13:54.947090392Z` |
| NextUpdate | `2026-10-17T01:13:54.947090202Z` |
| usableUntil | **`2026-10-30T01:13:54.947090392Z`** |
| Политика | `cve-db-updated-at-14d-v2`; UpdatedAt + 14 дней включительно |
| Состояние на момент proof | **`stale-but-usable`** |
| Предупреждения | **`DB_DATA_OLDER_THAN_24H`**, **`DB_PUBLICATION_OVERDUE`** |
| Signer | **`local-db-operator-v1` — локальный оператор, не Aqua** |

NextUpdate — ожидаемая публикация, **не** срок usableUntil. Сохранённая проверка DB не гарантирует сегодняшнюю актуальность или безопасность образа; браузер отображает evidence и не проверяет подпись криптографически. Локальная аттестация официального DB release не является подписью Aqua.

**Public pin не обновляется автоматически.** Старый LOCAL refresher/macOS scheduler для 8080 не управляет 8081. Не меняйте profile/overlay/pins/ключи вручную и не удаляйте release assets ради refresh. После usableUntil новые CVE admission обязаны отказывать, а исторические отчёты не становятся свежими. Согласованный public refresh — отдельная операторская работа, не реализованная этим usage guide.

## Финальная локальная валидация после обновления

- Полный API: **1302/1302 PASS**, 0 failed/skipped/cancelled; API TypeScript PASS.
- Полный UI `pnpm exec vitest run --maxWorkers=1`: PASS. Выполнен последовательно после native проверок, не подменён прежними результатами.
- `pnpm typecheck`, `pnpm lint`, `pnpm build`, `pnpm build:admin`: PASS; известное предупреждение Vite о chunks >500 kB сохранено.
- Launcher/LOCAL/CVE refresh/scheduler: **428/428 PASS**, 0 failed/skipped/cancelled.
- `git diff --check`: PASS до финальных docs-only дополнений.
- Native Debian и Node — два отдельных actual full-chain PASS, не universal OS/ecosystem/security qualification.

## Что ещё не принято целиком

Реальные deploy и два native PASS снимают прежний blocker «native NOT_RUN» для указанного public-среза. Они **не закрывают автоматически full TASK2 или весь диплом/продукт**. Полная scanner-negative/OS/ecosystem/resource-матрица, long-idle/reconnect/restart/cancellation qualification, отдельный runtime/host/LLM, production TLS/abuse/backup-restore acceptance и formal spec/tracker reconciliation требуют своей приёмки. Квитанция явно сохраняет `wholeSystemQualification:false`; metadata `qualified:false` не заменяется общим обещанием готовности.

[Текущий итог и исторические этапы](public-image-final-20261018.md). Старые документы NOT_RUN/HOLD сохраняют историю своих дат, но не являются инструкцией повторить уже завершённый recovery. Эта docs-only правка не выполняет тестов, Docker/lifecycle, сканов или изменений tracker/spec/state.
