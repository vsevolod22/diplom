# Полный локальный стенд и исправление длинного image reference

## Запуск

```sh
pnpm stand:local
pnpm stand:local:status
pnpm stand:local:stop
```

`stand:local` собирает и запускает detached project **dip-local-full**. Откройте **http://127.0.0.1:8080/register**, зарегистрируйте новый аккаунт, затем перейдите на **/scans/new**. Для первого запуска выберите **Alpine 3.20**, проверки **Secrets + SBOM + CVE + Image config**, подтвердите цель и нажмите «Запустить скан». Вход и регистрация находятся на `/login` и `/register`, не на API URL.

Это собранный frontend/nginx + настоящий Nest API + worker/Trivy + egress gateway + две постоянные SQLite-базы. Порты API/worker наружу не публикуются, web слушает только `127.0.0.1:8080`. Аккаунты/задания в старом Docker project и dev-auth на 5173 сюда не переносятся. Cookie привязаны к host, а не порту; для параллельной проверки auth-dev и полного стенда лучше использовать разные browser profiles.

## Сохранение и ограничения

- Новые volumes: `dip-local-full_auth_accounts`, `dip-local-full_scan_ledger`; сети также имеют префикс `dip-local-full`.
- Локальный signing secret создаётся эксклюзивно в `.local-stand/scan-jwt` (0600, directory0700), сохраняется между перезапусками, не выводится в argv/лог. `.local-stand` исключён из Git и Docker context.
- `stop` останавливает только проверенные контейнеры этого project, **не удаляет** volumes/accounts/reports/secret. Init containers с exit0 — нормальное завершение подготовки новых volumes.
- Старый `dip-auth-stand`, `.local-auth`, его env/ключи/volumes/HOLD не читаются и не мигрируются launcher'ом. Он отказывает при чужих/unlabelled ресурсах в своём namespace.
- Это loopback LOCAL profile с разрешением зарегистрированным локальным аккаунтам запускать ограниченные image scans, не публичный сервис и не общий произвольный Docker scanner. Target/check sets дополнительно проверяет сервер; показываемый nginx — условный профиль, не разрешение на любой образ.
- **CVE включён на текущей машине** через `.local-stand/cve.json`, отдельный LOCAL-only публичный ключ и immutable signed release. См. [local-cve-20261016.md](local-cve-20261016.md). На чистой установке отсутствие activation оставляет CVE выключенным; некорректная существующая activation блокирует запуск, а не ослабляет проверки. Провайдер ИИ, history, host/runtime capture не включены.
- После изменения UI повторите `pnpm stand:local`, чтобы пересобрать web. Обычный `pnpm dev:auth` подключает только auth API и не заменяет полный стенд.

## Исправление интерфейса

Длинный registry reference/digest расширял вложенные grid/flex tracks: при ширине viewport320 форма была868px, кнопка832px. Исправление в `src/features/scans/scan-a1.css` и `ScanCreatePage.tsx` ограничивает tracks `minmax(0,1fr)`, задаёт shrinkable children и перенос текста. Полный digest сохраняется, данные не обрезаются ellipsis/overflow-hidden.

Браузерная регрессия `tests-e2e/scan-create-long-reference.spec.ts`: **6/6 PASS** — 320/375/768/1280/1440px и1280px при200% CSS zoom. Форма теперь284/339/732/480/480px соответственно. Проверены текстовые fragments, подтверждение, чекбоксы, guard запуска и отсутствие overflow/clipping.

```sh
pnpm exec playwright test --config tests-e2e/scan-create-long-reference.config.ts
node --test scripts/test_local_stand.mjs
```

## Текущая CVE-проверка — 2026-10-16

`node tests-e2e/local-stand-live.mjs --cve` прошёл полный browser E2E за29.3s: четыре проверки на Alpine3.20, current signed DB/closed v2 metadata, owner report/render/reload/freshlogin. Secrets0, SBOM14, CVE0, Image config1. Дополнительный pinned архивный Alpine3.16 через owner HTTP завершился completed: Secrets0, SBOM14, **CVE4**, config1. Нет fake DB или снятых signature/source/freshness/read-only gates. Стенд оставлен UP.

Launcher status/up/stop поддерживает exact read-only binds на Docker Desktop/macOS (literal `/host_mnt` mapping только при согласованной declaration), не открывает private signing key. Текущие тесты launcher27/27, setup24/24, API639/639 и UI553/553 PASS; lint/typecheck PASS.

## Автообновление CVE

На текущей машине установлен отдельный macOS LaunchAgent `io.diplom.local-full.cve-refresh`, интервал6часов в пользовательской сессии. `pnpm cve:auto:status` проверяет загруженную конфигурацию и показывает последний bounded public status; `pnpm cve:refresh` выполняет ручную проверку. База обновлена до manifest `9dd4076…b43c`, UpdatedAt `2026-10-16T01:13:54.947090392Z`; последующий настоящий browser scan PASS за29.453s. Native launchd run завершился `unchanged` в11:36:12.831Z.

Обновлятор не запускает Docker Desktop или остановленный стенд, не меняет старый HOLD и production trust. При новом выпуске API кратковременно недоступен, worker завершает durable work до переключения. Подробности по безопасности, ошибкам, budget и сохранённому аудиту: [local-cve-auto-refresh.md](local-cve-auto-refresh.md). Совместные host-script тесты174/174, UI553/553, API639/639, lint/typecheck PASS.

## Историческая проверка до подключения CVE

`node tests-e2e/local-stand-live.mjs` создаёт только свой synthetic аккаунт и один настоящий scan на уже работающем `dip-local-full`, без Docker lifecycle и HTTP mocks. Аккаунт и отчёт остаются в новом стенде; credentials/cookies существуют только в памяти. В обычной проверке пользователю следует создавать свой аккаунт — чужие synthetic отчёты закрыты owner auth.

Финальный actual прогон **PASS**, 16.269s, scan `94309d49-0c0a-4617-9f7a-ea6c2408a24a`:

- UI registration/session/logout/login, HttpOnly/SameSite cookie — PASS.
- Long reference layout на собранном UI320/375/1280px, без clipping/overflow — PASS.
- Серверный eligibility, явные Secrets/SBOM/config и consent, один POST202 — PASS.
- Реальный Alpine3.20, worker state **completed**: Secrets checked0, SBOM checked14 packages, Image config checked1 finding.
- Настоящие results/SBOM endpoints и DOM agreement, reload, список и fresh browser context login с тем же сохранённым report — PASS.
- Anonymous401, внутренний JWT-route404, LLM context disabled, zero pageerrors/externalrequests/unwantedmutations — PASS.
- Браузер закрыт, **стенд оставлен UP для пользователя**.

Два предшествующих прогона успешно завершили worker scan, но тест остановился на ошибочных требованиях optional `Secrets.checkedAt`, затем `status.imageReference`. Исправлены именно тестовые ожидания по текущему wire contract; последний полный прогон прошёл. Предыдущие отчёты не выдаются за PASS, повторных POST в одном прогоне не было.

Общий frontend Vitest **553/553 PASS**, launcher tests **13/13 PASS**, typecheck/ESLint PASS. Новый web образ также отдаёт required license notice HTTP200; stale Dockerignore-exclusions четырёх tracked notice-файлов удалены. Raw sanitized runtime receipt — в игнорируемом `test-results/local-stand-live.json`, без credentials.

Исторический прогон выше не включал CVE; новая CVE-приёмка описана отдельно. Ни один из них не является восстановлением старых данных, ручной VoiceOver-приёмкой, arbitrary Engine/host scan или production readiness.
