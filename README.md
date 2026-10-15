# Диплом — анализ безопасности OCI-образов

Веб-приложение для запуска разрешённых проверок образов, просмотра CVE, SBOM и Secrets, событий задания и доказательной ИИ-сводки/чата. React 19 + TypeScript + Vite, NestJS, SQLite ledger/outbox и изолированный worker с Trivy. Демонстрационные данные явно отделены от реального сканирования.

## Текущее состояние

Исходники и локальные проверки сведены в общий baseline. **Развёртывание на сохранённых пользовательских данных не завершено.** Старый Docker-стенд находится под HOLD после прерванной сохранительной миграции; не запускайте на нём `stand:auth`, refresh/recreate helpers, удаление контейнеров или volumes без отдельной проверки восстановления. См. [итоговую матрицу](docs/release-readiness-20261015.md) и [операционный HOLD](docs/deployment/hold-handoff-20261015.md).

Зелёные unit/browser tests не означают готовность публичного сервиса. Для публикации нужны TLS, ограничение злоупотреблений, проверенные backup/restore и отдельная runtime-приёмка. ИИ и runtime/host capabilities включаются отдельно; наличие кода или аккаунта не предоставляет разрешение на сканирование.

## Быстро посмотреть интерфейс

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

Описание отдельного нового окружения: [server/deploy/README.md](server/deploy/README.md). Исторический launcher `pnpm stand:auth` предназначен для loopback `127.0.0.1:8080` и persistent volumes; **сейчас его нельзя использовать поверх сохранённого HOLD-стенда**. Новый project с пустыми volumes не восстанавливает старые данные.

На локальном browser ingress разрешён только ограниченный image scan `library/alpine`; Secrets/SBOM и CVE имеют независимые outcomes. CVE требует проверенного подписанного offline release; непроверенная/неподдерживаемая категория не означает ноль проблем. `/api/v1/scans` — внутренний JWT API, снаружи он не должен публиковаться. Режим всех локальных аккаунтов не предназначен для публичного доступа; production enrollment использует ID, не email.

OpenRouter key вводится оператором только через скрытый локальный ввод `python3 scripts/set-openrouter-key.py`. Не передавайте ключ агенту/в чат, argv или Vite env. Утилита не активирует провайдера и не выполняет запросы. Подробности: [server/README.md](server/README.md).

## Навигация по документации

- [Финальная проверка и незакрытые критерии](docs/release-readiness-20261015.md)
- [Архитектура](docs/architecture/README.md)
- [Backend/API](server/api/README.md)
- [Runtime subsystem](server/runtime/docs/operator-runbook.md)
- [Требования и исторические проектные решения](docs/TZ.md)

Исторические evidence/manifests фиксируют свои версии исходников и результаты. Изменение текущего кода не переписывает их хеши и не превращает прежний proof в новую runtime-квалификацию.
