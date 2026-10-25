# Диплом — анализ безопасности OCI-образов

Веб-приложение для запуска разрешённых проверок образов, просмотра CVE, SBOM и Secrets, событий задания и доказательной ИИ-сводки/чата. React 19 + TypeScript + Vite, NestJS, SQLite ledger/outbox и изолированный worker с Trivy. Демонстрационные данные явно отделены от реального сканирования.

## Текущее состояние — 25.10.2026: public8081 в build HOLD

**Public scanner на http://127.0.0.1:8081 сейчас НЕ доступен (HTTP000).** Одно обновление остановилось на `build-submit-worker`, audit `deploy-2c9ed08b8269264b09bf14eb6189a649`, исходная причина `unclassified`. При последующей read-only проверке Docker вернул отдельный **blob input/output error** при чтении retained init image; это не доказанная причина worker build. Original four-store backup/checkpoint/HOLD сохранены. 8080 теперь HTTP500, точная причинность не установлена; его lifecycle не изменялся. **Ожидается отдельное разрешение владельца на перезапуск Docker Desktop**, затрагивающий защищённый8080. Не повторять normal `up`, старые recovery tokens, prune или удаление lock. [Актуальная точка продолжения](docs/public-product-handoff-20261025.md); READY от22.10 ниже — историческое evidence, не текущий runtime.

**Исторический browser scan от22.10, не новая приёмка:** Node scan завершился `completed`, все четыре checks `checked`; report/counts/filters/history/reload/fresh login и missing-key readiness прошли. При этом overall smoke остаётся **FAILED safety REQUEST_GUARD**: 3 заблокированных запроса без установленной причины; это не полный browser acceptance PASS. [Actual attempt2](docs/public8081launch-20261022.attempt2.md). Для сканирования откройте `/register`, затем `/scans/new`, введите public Docker Hub reference, выберите `linux/amd64` и checks, подтвердите цель. Чат находится на странице своего завершённого отчёта.

**8080 остаётся защищённым старым окружением**, до нового maintenance HTTP200, после — HTTP500 без установленной причины;  команды его lifecycle ниже — историческая документация, не указание запускать их на этой машине. Public CVE v2 migration/fresh activation выполнены ранее; public scheduler и настоящий post-LLM refresh ещё не квалифицированы. **Public ИИ настроен:** с разрешения владельца ключ из `server/.env.openrouter.local` перенесён в private state и отдельный API-only readonly volume. Исходные env не изменены; ключ не передаётся в браузер/Git/логи. OpenRouter authentication вернул HTTP200. Настроен строго бесплатный `xingchen-agi/xing4.0-29b-a4b:free` → `phala`, без fallback; настоящий completion probe получил **HTTP429**, точная причина лимита/отказа не установлена. Успешная генерация чата и перевода пока не подтверждена. Не повторяйте key provisioning и не сбрасывайте квоту после failed/dispatched попытки.

**Новые source fixes проверены, rollout НЕ завершён:** API1346/1346 и UI742/742 PASS, typecheck/lint/main/admin builds PASS; новые recovery offline88/88 и browser-runner59/59 PASS. Finite provider errors, строгий JSON/NDJSON wire и45s translation deadline внедрены в source; `russian-prose-v2` требует свежего context/consent. Успешные real chat/translation по-прежнему UNVERIFIED; новая native попытка не запускалась. Vite chunk warning и known intermittency не объявлены исправленными. DOC15/DOC16v3 applied, новых task done нет. Два харнесса с шестью реальными агентами завершены, browser outcome blocked, не app PASS.

**Русский перевод описаний реализован:** в подробностях уязвимости у конкретного источника нажмите «Прочитать условия перевода», подтвердите отдельное согласие и «Перевести на русский». При успешном ответе появятся маркировка машинного перевода и переключатель «Оригинал / Перевод»; исходный текст, язык источника, CVE/TEMP, severity/CVSS и provenance не меняются. Открытие карточки не отправляет текст провайдеру автоматически. Summary/chat также запрашивают русский текст. [Контракт, actual checks и текущие blockers](docs/public-ai-translation-20261022.md). NDJSON — доставка завершённого ответа, не native token streaming.

### Исторический LOCAL профиль (8080 защищён, не управлять для запуска public8081)

Полный локальный стенд запускается через `pnpm stand:local` на **http://127.0.0.1:8080**: собранный frontend/nginx, Nest API, постоянные SQLite-базы, worker и gateway. Проверен настоящий UI-запуск Secrets/SBOM/CVE/Image config с отчётом, reload и повторным входом. Это отдельный project `dip-local-full` с новыми данными, не восстановление старого окружения. **Развёртывание на сохранённых пользовательских данных не завершено.** Старый Docker-стенд находится под HOLD после прерванной сохранительной миграции; не запускайте на нём `stand:auth`, refresh/recreate helpers, удаление контейнеров или volumes без отдельной проверки восстановления. См. [итоговую матрицу](docs/release-readiness-20261015.md) и [операционный HOLD](docs/deployment/hold-handoff-20261015.md).

Зелёные unit/browser tests не означают готовность публичного сервиса. Для публикации нужны TLS, ограничение злоупотреблений, проверенные backup/restore и отдельная runtime-приёмка. ИИ и runtime/host capabilities включаются отдельно; наличие кода или аккаунта не предоставляет разрешение на сканирование.

## Полный локальный запуск с настоящим scanner

Нужен запущенный Docker Desktop. Из корня `diplom`:

```sh
pnpm stand:local         # собрать и запустить в фоне; первый запуск может занять несколько минут
pnpm stand:local:status  # состояние только нового dip-local-full
pnpm stand:local:stop    # остановить без удаления аккаунтов и отчётов
```

Откройте http://127.0.0.1:8080/register и создайте **новый локальный аккаунт** с паролем от 12 символов. Затем откройте http://127.0.0.1:8080/scans/new, выберите **Alpine 3.20**, отметьте **Secrets, SBOM, CVE, Image config**, подтвердите цель и запустите скан. Результат появится на странице задания и останется в `/scans` после повторного входа. Здесь нужны страницы `/scans`, не `/demo/scans`; порт `5173` — другой dev-режим.

**На текущей машине CVE подключён и настроено обновление каждые 6 часов** через отдельный macOS LaunchAgent. Текущая подписанная локальным оператором база имеет UpdatedAt `2026-10-16T01:13:54.947090392Z`; настоящий browser scan с новой базой проверен. `pnpm cve:auto:status` показывает расписание и последний результат, `pnpm cve:refresh` запускает проверку вручную. [Автообновление и ограничения](docs/local-cve-auto-refresh.md), [первоначальное подключение и доверие](docs/local-cve-20261016.md). Alpine 3.20 дал 0 CVE, архивный **Alpine 3.16 — 4 CVE** на первоначальной базе; это результаты конкретных сканов, не гарантия безопасности. На новой установке без `.local-stand/cve.json` CVE остаётся выключен. ИИ требует отдельной настройки провайдера/согласия; host/runtime capture не включены.

Аккаунты/отчёты сохраняются в отдельных volumes `dip-local-full_auth_accounts` и `dip-local-full_scan_ledger`. Подпись локального API сохраняется в игнорируемом `.local-stand/scan-jwt`; файл не печатается и не вращается при рестарте. Не удаляйте его или volumes ради перезапуска. Launcher не читает private env и не изменяет старый project `dip-auth-stand`/HOLD. Стенд доступен только через loopback; не публикуйте его в сеть.

## Новый расширенный image-only профиль

**Историческая приёмка 18.10.2026, не текущий runtime:** отдельный стенд `dip-public-images` тогда работал на http://127.0.0.1:8081; текущий runtime снова восстановлен READY, см. актуальную проверку 22.10 выше. Координатор завершил guarded recovery/redeploy с проверенными quiescent SQLite backups и сохранением аккаунтов, истории, JWT и volumes этого public-стенда; исходный public HOLD архивирован. Старый **8080 остаётся отдельным legacy-профилем**, не изменён, HTTP 200 подтверждён координатором. Это не снятие иных исторических HOLD и не перенос данных между стендами.

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

Public CVE уже переведена на собственные v2 state/trust; ранее выполнена настоящая fresh upstream activation. Последняя подтверждённая UpdatedAt `2026-10-20T19:12:26.430296739Z`, manifest `sha256:5903d201b3dc68dda334b9a9397ed51bd7956d834f43ab4edae6844a18912ced`. Freshness перепроверять при использовании; usable не означает fresh. Public scheduler ещё не установлен/не квалифицирован, post-LLM four-store refresh не выполнен. Подпись `local-db-operator-v1` — аттестация **локального оператора, не Aqua**. Старый LOCAL updater/scheduler не управляет 8081; pins вручную не менять.

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
