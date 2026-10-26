# Диплом — анализ безопасности OCI-образов

Веб-приложение для запуска разрешённых проверок образов, просмотра CVE, SBOM и Secrets, событий задания и доказательной ИИ-сводки/чата. React 19 + TypeScript + Vite, NestJS, SQLite ledger/outbox и изолированный worker с Trivy. Демонстрационные данные явно отделены от реального сканирования.

## Текущее состояние — 26.10.2026

**Scanner работает: http://127.0.0.1:8081. Защищённый8080 также отвечает HTTP200.** Новые сборки развёрнуты с сохранением accounts/reports/JWT/history/quota; operation lock отсутствует. Проверены7services/6networks, API healthy, API-only readonly key volume и worker4GiB/CPU1/PIDs128. Старые recovery tokens уже consumed — не повторять. [Актуальный итог автоматизации и настоящей проверки](docs/public-automation-20261026-final.md). Последний rollout `deploy-ed3d33be2f2b7fcc19e33544cea7b195` завершён READY;425файлов build-source сверены побайтно. [Предыдущая финализация](docs/public-finalization-20261026.md) сохранена как история.

### Сканирование и прогресс

Откройте `/register` или `/login`, затем `/scans/new`: введите public Docker Hub reference, выберите `linux/amd64`, проверки и подтвердите цель. **Вся строка скана кликабельна**, включая название. На странице и в списке показывается **приблизительный процент**, а не25%закаждуюпроверку: загрузка и анализ уязвимостей весят больше конфигурации, оценка постепенно меняется по времени наблюдения и подтверждённым итогам. Это некалиброванная эвристика, не измеренный процент работы и не ETA; невидимые внутренние повторы могут её завышать.100%показывается только для подтверждённого `completed`, не для failed/cancelled. Серверный `percent:null` не подменён. Исходы проверок показаны компактными плитками; технические версии раскрываются отдельно.

Реальный browser scan26.10 завершился `completed`, все4checks `checked`: **161CVE,0DebianTEMP,4страницы** на конкретных pinned image/DB. Свежий вход, ownership404/UI denial и сохранность отчёта прошли. Отдельный native progress/cancel workflow — **10/10PASS**: после отмены сохранён завершённый config-check; остальные проверки остались unknown, не0. Старые FAIL сохранены отдельно, не переписаны.

### Настройки языка и автоматическая ИИ-сводка

В `/account` выберите **«Язык отчёта: оригинал / русский»** и режим краткой ИИ-сводки, затем сохраните настройки. Они привязаны к аккаунту **в этом браузере**. До явного сохранения автоматика выключена; рядом раскрыты точная бесплатная пара, передаваемые поля и ограничения. После включения сводка запрашивается автоматически при завершении скана, без «Получить сводку». Чат и поле вопроса открываются сразу; сам вопрос отправляется пользователем. При выбранном русском языке открытая карточка advisory автоматически переводит свои разрешённые поля; весь отчёт заранее провайдеру не рассылается. Закрытие, отзыв выбора или смена аккаунта отменяют ожидание; очереди ограничены, автоматических повторов отказов нет. Ключ уже подключён API-only readonly — вводить его повторно не нужно.

Новые summary/chat запрашивают русский текст и проходят консервативные language/grounding guards; теперь запрашивается точная JSON Schema для каждой операции. Находки scanner отделены от интерпретации ИИ. Оригинальные advisory не переписываются. Готовая public-сводка читается без генерации после reload/повторного входа, пока сохраняется ограниченный кэш процесса API; **не переживает перезапуск API или вытеснение**. История чата сохраняет отдельный durable-контракт. NDJSON доставляет завершённый проверенный ответ, **не native token streaming**.

**Успешная реальная генерация всё ещё не принята.** Последний native attempt `60aa9db1…`: scan/оценочныйпрогресс/покрытие/отчёт/сразуоткрытыйчат/settings-original/passive-summary-404/anonymous401/preservation/safetyPASS. Один автоматический summary POST получил **application503 `LLM_REQUEST_ABORTED`, `deadline/timeout`**; это не доказанный upstream503. ConsumptionUNKNOWN, chat/translationPOST0 — дальнейшая генерация остановлена. Более ранние provider429 и translation invalid_content остаются историческими фактами; новая попытка не установила их причину. Фиксированная бесплатная пара OpenRouter `xingchen-agi/xing4.0-29b-a4b:free` → `phala` не менялась; paid/автоматического fallback и refund/reset нет. Смена профиля или лимитов требует отдельного решения, а не скрытого повтора.

### CVE, проверки и процесс

Новая public CVE release активирована с four-store preservation; UpdatedAt **2026-10-25T19:10:35.479132794Z**. Отдельный public scheduler установлен и проходит status-проверку: **каждые6часов**, без RunAtLoad/KeepAlive. Успешный periodic-run receipt отдельно не заявляется. Локальная подпись оператора — **не Aqua publisher signature**; LOCAL8080 updater не используется для8081.

Свежий полный API: **1411/1411PASS**. Полный UI: **994/994PASS** до последних узких правок; после них отдельно прошли143translation/160progress/366summary-targeted и130offline-runner тестов. Старые два paging timeout в новом полном прогоне прошли, но их первопричина не объявлена исправленной. Typecheck/lint/main+admin buildsPASS; Vite chunk warning сохраняется. Новая работа выполнена пятью параллельными авторами с отдельными reviewer/spec/browser/security lanes. Applied DOC2v10/DOC8v6/DOC9v4/DOC15v5/DOC16v5; TASK9/TASK42 не закрыты поверх непроверенных критериев.

### Исторический LOCAL профиль (8080 защищён, не управлять для запуска public8081)

Полный локальный стенд запускается через `pnpm stand:local` на **http://127.0.0.1:8080**: собранный frontend/nginx, Nest API, постоянные SQLite-базы, worker и gateway. Проверен настоящий UI-запуск Secrets/SBOM/CVE/Image config с отчётом, reload и повторным входом. Это отдельный project `dip-local-full` с новыми данными, не восстановление старого окружения. **Развёртывание на сохранённых пользовательских данных не завершено.** Старый Docker-стенд находится под HOLD после прерванной сохранительной миграции; не запускайте на нём `stand:auth`, refresh/recreate helpers, удаление контейнеров или volumes без отдельной проверки восстановления. См. [итоговую матрицу](docs/release-readiness-20261015.md) и [операционный HOLD](docs/deployment/hold-handoff-20261015.md).

Зелёные unit/browser tests не означают готовность публичного сервиса. Для публикации нужны TLS, ограничение злоупотреблений, проверенные backup/restore и отдельная runtime-приёмка. ИИ и runtime/host capabilities включаются отдельно; наличие кода или аккаунта не предоставляет разрешение на сканирование.

## Исторический LOCAL запуск (не выполнять на этой машине для public8081)

Ниже сохранена инструкция отдельного LOCAL-профиля8080. Сейчас он защищён; для работающего public8081 launcher не нужен. Не запускайте LOCAL команды обслуживания без отдельного разрешения.

Для новой независимой LOCAL установки требовался запущенный Docker Desktop. Из корня `diplom`:

```sh
pnpm stand:local         # собрать и запустить в фоне; первый запуск может занять несколько минут
pnpm stand:local:status  # состояние только нового dip-local-full
pnpm stand:local:stop    # остановить без удаления аккаунтов и отчётов
```

Откройте http://127.0.0.1:8080/register и создайте **новый локальный аккаунт** с паролем от 12 символов. Затем откройте http://127.0.0.1:8080/scans/new, выберите **Alpine 3.20**, отметьте **Secrets, SBOM, CVE, Image config**, подтвердите цель и запустите скан. Результат появится на странице задания и останется в `/scans` после повторного входа. Здесь нужны страницы `/scans`, не `/demo/scans`; порт `5173` — другой dev-режим.

**Исторически для LOCAL8080 CVE был подключён и настроено обновление каждые 6 часов (не public8081)** через отдельный macOS LaunchAgent. Текущая подписанная локальным оператором база имеет UpdatedAt `2026-10-16T01:13:54.947090392Z`; настоящий browser scan с новой базой проверен. `pnpm cve:auto:status` показывает расписание и последний результат, `pnpm cve:refresh` запускает проверку вручную. [Автообновление и ограничения](docs/local-cve-auto-refresh.md), [первоначальное подключение и доверие](docs/local-cve-20261016.md). Alpine 3.20 дал 0 CVE, архивный **Alpine 3.16 — 4 CVE** на первоначальной базе; это результаты конкретных сканов, не гарантия безопасности. На новой установке без `.local-stand/cve.json` CVE остаётся выключен. ИИ требует отдельной настройки провайдера/согласия; host/runtime capture не включены.

Аккаунты/отчёты сохраняются в отдельных volumes `dip-local-full_auth_accounts` и `dip-local-full_scan_ledger`. Подпись локального API сохраняется в игнорируемом `.local-stand/scan-jwt`; файл не печатается и не вращается при рестарте. Не удаляйте его или volumes ради перезапуска. Launcher не читает private env и не изменяет старый project `dip-auth-stand`/HOLD. Стенд доступен только через loopback; не публикуйте его в сеть.

## Новый расширенный image-only профиль

**Историческая приёмка 18.10.2026, не текущий runtime:** отдельный стенд `dip-public-images` тогда работал на http://127.0.0.1:8081; текущий runtime восстановлен READY и обновлён26.10, см. [актуальный итог](docs/public-progress-20261026-final.md). Координатор завершил guarded recovery/redeploy с проверенными quiescent SQLite backups и сохранением аккаунтов, истории, JWT и volumes этого public-стенда; исходный public HOLD архивирован. Старый **8080 остаётся отдельным legacy-профилем**, не изменён, HTTP 200 подтверждён координатором. Это не снятие иных исторических HOLD и не перенос данных между стендами.

После отдельно проверенного восстановления 8081 не нужно повторять launcher/recovery для обычного использования. Откройте **отдельный browser profile или выделенный incognito context**, перейдите на http://127.0.0.1:8081/register и создайте **новый аккаунт** с паролем от 12 символов. Cookies одного hostname не разделяются номером порта: не используйте в этом же context сессию 8080. Затем откройте http://127.0.0.1:8081/scans/new, вручную введите один из canonical references:

```text
registry-1.docker.io/library/debian:bookworm-slim
registry-1.docker.io/library/node:22.14.0-alpine3.21
```

Выберите Secrets, SBOM, CVE и Image config, дождитесь свежего серверного допуска, подтвердите цель/область и отправьте один запуск. Отчёт доступен в `/scans`, включая reload и повторный вход **на 8081**. Поиск — только подсказка; новый scan заново проверяет target, readiness и DB. POST 202 ещё не означает завершённую проверку.

**Исторические native browser/API/UI proofs от 18.10.2026 (не повторялись на нынешнем LLM candidate):**

| Запуск 18.10.2026, UTC | Secrets | SBOM | Уязвимости | Image config |
| --- | --- | --- | --- | --- |
| Debian `bookworm-slim`, 14:03:09.760–14:04:25.768 | checked, 0 | checked, 88; Debian 12.15 | checked, 241 всего: **236 CVE + 5 Debian TEMP advisories**, не 241 CVE | checked, 1 |
| Node `22.14.0-alpine3.21`, 14:05:06.605–14:06:18.591 | checked, 0 | checked, 217; npm 200 | checked, **158 CVE + 0 Debian TEMP** | checked, 1 |

Это результаты конкретных pinned сканов, не обещание таких же результатов для будущего tag. Проверены actual manual entry → fresh eligibility → POST → native worker → report → reload → fresh login; HTTP/OCI/scanner не подменялись. [Полная безопасная Node-квитанция](docs/public-image-node-native-20261018.json), [текущий статус и границы доказательств](docs/public-image-final-20261018.md).

Профиль `public-hub-amd64-v1` допускает **только публичные official/namespaced Docker Hub images, IMAGE и linux/amd64** поддерживаемого формата и размера — **не буквально любой образ/registry/OS**. Worker ограничен **4 GiB RAM без дополнительного swap**, CPU 1, PIDs 128 и tmpfs 2304 MiB; acquisition/archive/report limits конечны. Неподдерживаемые форматы/экосистемы, EOL, неизвестный inventory и превышение ресурсов не считаются checked/0. Entry point исследуемого образа не запускается; Docker socket worker не получает. Runtime/host/LLM этим профилем не включаются.

Public CVE использует собственные v2 state/trust. После исторического download failure выполнена отдельная успешная changed-release activation с four-store preservation: UpdatedAt `2026-10-25T19:10:35.479132794Z`, manifest `sha256:e1af977c90fb06ebf3d5123afb831b89d659e7e0a3fc6231e4f9e42d85c9ec98`. Freshness перепроверять при использовании; usable не означает fresh. Отдельный public scheduler установлен, loaded/statusPASS, каждые6часов; completed periodic-run receipt пока не подтверждён. Пустая staging архивирована без удаления historical evidence; прежняя причина download failure остаётся UNKNOWN. Подпись `local-db-operator-v1` — аттестация **локального оператора, не Aqua**. Старый LOCAL updater/scheduler не управляет8081; pins вручную не менять.

[Как пользоваться 8081 и читать ограничения](docs/public-image-ready-20261018.md). Два native PASS снимают прежнее утверждение «native NOT_RUN», но **не закрывают всю TASK2, полную OS/ecosystem/negative-матрицу или production acceptance**. Исторические source-only и HOLD-этапы сохраняют свои даты и доказательства.

## Быстро посмотреть только интерфейс

```sh
pnpm install --frozen-lockfile
pnpm dev
```

Откройте `/demo/scans` по адресу, напечатанному Vite. Это **fixture-режим**, без Docker и настоящего сканирования. Клиентский и административный entrypoints собираются командами `pnpm build` и `pnpm build:admin`; отдельная админка остаётся каркасом, не готовой системой управления.

## Регистрация и сессия без Docker

```sh
pnpm dev:auth
```

Откройте именно http://127.0.0.1:5173/register, задайте email и пароль не короче 12 символов, проверьте `/account`, выход и `/login`. `/demo/scans` доступен без регистрации. Нужны свободные порты 5173 и 3001; `Ctrl+C` завершает оба процесса.

Локальный launcher привязывает Vite/NestJS к loopback, проксирует только `/api/v1/auth` и хранит аккаунты в игнорируемой Git базе `.local-auth/auth.sqlite`. Он не публикует внутренний scan API. Cookie для `127.0.0.1` не переносится на `localhost`. Не копируйте базу, пароли или private env в репозиторий.

## Проверки

```sh
pnpm check                    # typecheck, lint, UI/API/broker tests, обе сборки
pnpm test:e2e                 # Chromium, управляемый Vite, без реального scanner
pnpm test:report-integration  # Chromium + настоящий временный Nest API/SQLite
```

Точечные команды: `pnpm test`, `pnpm test:api`, `pnpm test:broker`, `pnpm typecheck`, `pnpm lint`. API/broker используют зависимости из workspace; браузерным проверкам нужен установленный Chromium для Playwright. Интеграционная проверка создаёт синтетический отчёт и тестовые аккаунты во временном каталоге, работает только через loopback и закрывает браузер/API/listeners в конце. Она **не обращается к Trivy, Docker или LLM** и не принимает production deployment.

Большие Markdown/syntax chunks пока вызывают предупреждения Vite о размере >500 kB. Это известное ограничение, не скрытое увеличением порога.

## Docker-стенд

Для обычной локальной проверки используйте **`pnpm stand:local`**, описанный выше. Операционные deployment-границы: [server/deploy/README.md](server/deploy/README.md). Исторический launcher `pnpm stand:auth` предназначен для loopback `127.0.0.1:8080` и persistent volumes; **сейчас его нельзя использовать поверх сохранённого HOLD-стенда**. Новый project с пустыми volumes не восстанавливает старые данные.

На локальном browser ingress разрешён только ограниченный image scan `library/alpine`; Secrets/SBOM и CVE имеют независимые outcomes. CVE требует проверенного подписанного offline release; непроверенная/неподдерживаемая категория не означает ноль проблем. `/api/v1/scans` — внутренний JWT API, снаружи он не должен публиковаться. Режим всех локальных аккаунтов не предназначен для публичного доступа; production enrollment использует ID, не email.

OpenRouter key вводится оператором только через скрытый локальный ввод `python3 scripts/set-openrouter-key.py`. Не передавайте ключ агенту/в чат, argv или Vite env. Утилита не активирует провайдера и не выполняет запросы. Подробности: [server/README.md](server/README.md).

## Навигация по документации

- [Финальная проверка и незакрытые критерии](docs/release-readiness-20261015.md)
- [Проверки testing-задач и актуальная синхронизация Flownix](docs/testing-followup-20261016.md)
- [Архитектура](docs/architecture/README.md)
- [Backend/API](server/api/README.md)
- [Runtime subsystem](server/runtime/docs/operator-runbook.md)
- [Требования и исторические проектные решения](docs/TZ.md)

Исторические evidence/manifests фиксируют свои версии исходников и результаты. Изменение текущего кода не переписывает их хеши и не превращает прежний proof в новую runtime-квалификацию.
