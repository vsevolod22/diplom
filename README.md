# Диплом — анализ безопасности OCI-образов

Веб-приложение для запуска разрешённых проверок образов, просмотра CVE, SBOM и Secrets, событий задания и доказательной ИИ-сводки/чата. React 19 + TypeScript + Vite, NestJS, SQLite ledger/outbox и изолированный worker с Trivy. Демонстрационные данные явно отделены от реального сканирования.

## Текущее состояние

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

**На текущей машине CVE уже подключён**: подписанный локальным оператором offline release с фактическим UpdatedAt `2026-10-15T19:09:25.631494278Z`. Alpine 3.20 дал 0 CVE, архивный **Alpine 3.16 — 4 CVE**; это результаты конкретных сканов, не гарантия безопасности. На новой установке без `.local-stand/cve.json` CVE остаётся выключен. [Подключение базы и проверка доверия](docs/local-cve-20261016.md). ИИ требует отдельной настройки провайдера/согласия; host/runtime capture не включены.

Аккаунты/отчёты сохраняются в отдельных volumes `dip-local-full_auth_accounts` и `dip-local-full_scan_ledger`. Подпись локального API сохраняется в игнорируемом `.local-stand/scan-jwt`; файл не печатается и не вращается при рестарте. Не удаляйте его или volumes ради перезапуска. Launcher не читает private env и не изменяет старый project `dip-auth-stand`/HOLD. Стенд доступен только через loopback; не публикуйте его в сеть.

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
- [Архитектура](docs/architecture/README.md)
- [Backend/API](server/api/README.md)
- [Runtime subsystem](server/runtime/docs/operator-runbook.md)
- [Требования и исторические проектные решения](docs/TZ.md)

Исторические evidence/manifests фиксируют свои версии исходников и результаты. Изменение текущего кода не переписывает их хеши и не превращает прежний proof в новую runtime-квалификацию.
