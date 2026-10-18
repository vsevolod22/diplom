# Public image-only — финальный handoff нового инкремента

## Текущий статус — 2026-10-18, после 14:06 UTC

**Развёртывание отдельного public-профиля на `http://127.0.0.1:8081` восстановлено; настоящие Debian и Node native proofs — PASS.** Это обновление документации по сообщению координатора и сохранённой безопасной Node-квитанции, не новый Docker/live/test запуск автором документа.

Координатор сообщает успешный guarded recovery/redeploy: проверены quiescent SQLite backups, сохранены accounts/history/JWT/volumes public-стенда, исходный public HOLD архивирован. **8080 не изменён, HTTP 200**; он остаётся отдельным legacy-профилем. Это не миграция legacy-данных в public и не снятие других исторических HOLD. Старые записи «start/build HOLD», «native NOT_RUN», «Docker недоступен» ниже описывают уже пройденные этапы, а не текущее состояние 8081. Не повторять их recovery/launch команды ради обычного использования работающего UI.

### Фактические native результаты

| Target / scan | Время UTC, 18.10.2026 | Secrets | SBOM | Уязвимости | Config |
| --- | --- | --- | --- | --- | --- |
| `registry-1.docker.io/library/debian:bookworm-slim` · `b2c8f335-f1e8-4c0e-be33-561bd0cda1a6` | 14:03:09.760Z → 14:04:25.768Z | checked, 0 | checked, 88; Debian **12.15** | checked, **241 всего: 236 CVE + 5 Debian TEMP advisories** | checked, 1 |
| `registry-1.docker.io/library/node:22.14.0-alpine3.21` · `4dfdcc89-c78f-415f-b73b-74cde4798a4d` | 14:05:06.605Z → 14:06:18.591Z | checked, 0 | checked, 217; Alpine 3.21.3, npm 200 | checked, **158 CVE + 0 Debian TEMP** | checked, 1 |

Debian: coordinator-reported actual native proof PASS/completed. Вывод его receipt был обрезан; разделение 236/5 соответствует worker replay и проверено assertions proof, но полный Debian JSON здесь не выдумывается и не заменяется Node receipt. Для Debian отсутствие npm evidence не означает доказанное отсутствие Node-пакетов: `NODE_INVENTORY_UNKNOWN` остаётся unknown, не absent.

Node: [полный безопасный receipt](public-image-node-native-20261018.json) прочитан; `PASS_SINGLE_NATIVE_TARGET`, `nativeExecution:true`, `completed`, один scan POST, 0 page errors/external browser requests, `mockedHttp:false`, `injectedOciOrScanner:false`, browser cleanup подтверждён. Реальный pinned digest — `sha256:01393fe5a51489b63da0ab51aa8e0a7ff9990132917cf20cfc3d46f5e36c0e48`, `linux/amd64`. Proof проверяет actual manual reference/checks/consent, fresh eligibility, native результаты, receipt/DB/identity/counts, UI, reload и fresh own login. Существующий отдельный controlled Chromium proof остаётся controlled evidence, а не источником этих native чисел.

### Рабочее использование и ограничения

[Русская инструкция: открыть 8081, зарегистрировать новый аккаунт, вручную выбрать canonical target и прочитать результат](public-image-ready-20261018.md). Не смешивать browser context/cookies 8080 и 8081. Профиль только public Docker Hub official/namespaced images, IMAGE, linux/amd64 и конечные ресурсы: worker **4 GiB**, без дополнительного swap, CPU 1/PIDs 128/tmpfs 2304 MiB. Это не любой образ/registry/OS/ecosystem и не включение runtime/host/LLM. Ноль Secrets/CVE не является гарантией безопасности; config checked 1 — находка metadata, не выполнение контейнера.

Public DB pinned, **без автообновления**: UpdatedAt **`2026-10-16T01:13:54.947090392Z`**, usableUntil **`2026-10-30T01:13:54.947090392Z`**. Node receipt показывает `stale-but-usable` на момент проверки и warnings **`DB_DATA_OLDER_THAN_24H` / `DB_PUBLICATION_OVERDUE`**. NextUpdate не равен usableUntil. Подпись **`local-db-operator-v1` — локальная аттестация, не подпись Aqua**; браузер не проверяет её криптографически. Старый LOCAL refresh/scheduler не обновляет public pin. После expiry новые CVE admission должны отказывать, а сохранённый исторический отчёт не доказывает сегодняшнюю свежесть.

### Что этот PASS не закрывает

Прежний blocker «не было настоящего public native/deploy» снят указанными результатами. **Полная TASK2 и весь продукт автоматически не приняты**: два точных target не заменяют полную OS/ecosystem/format/resource/negative-матрицу, long-idle/reconnect/restart/cancellation qualification, public production/TLS/abuse/backup-restore acceptance, отдельный runtime/host/LLM и требуемую formal spec/tracker reconciliation. Конкретные оставшиеся критерии и статусы сверяет координатор; этот docs-only проход не выполняет tests и не меняет tracker/spec. В Node receipt `wholeSystemQualification:false` и `imageProfile.qualified:false`; single-target PASS не присваивает legacy qualification stamp.

## Исторические этапы 2026-10-18 — сохранены, не текущие инструкции

Следующие разделы фиксируют раннее состояние **до успешного recovery и native запусков 14:03–14:06 UTC**. Их NOT_RUN/daemon/start-HOLD assertions и «следующий внешний шаг» читать только в историческом контексте. Прежние test totals, review verdicts, artifacts и spec/tracker disposition не переписаны в новые результаты и не объявлены повторно проверенными.

### Раннее native продолжение — историческая запись 2026-10-18

Docker уже доступен;4 новых public images действительно собраны. Launcher compatibility исправлена с66/66 tests и независимым review, однако actual start остановился после создания2 сетей (0containers/volumes); новый start-HOLD сохранён. Native scan ещё NOT_RUN. Удалены4 конкретных unused image tags, ни один контейнер/volume/network не удалён. Для продолжения требуется отдельный release9 пустых, но исторически retained proof-сетей. Existing LOCAL8080=200. Исторический handoff этого этапа: [public-image-native-attempt-20261018.md](public-image-native-attempt-20261018.md). Ниже сохранён итог предыдущего source-only этапа.

## Решение и граница

По запросу владельца реализован отдельный optional `public-hub-amd64-v1`, вместо формального снятия Alpine/exact-nginx allowlist. Он допускает проверку публичных Docker Hub official/namespaced образов поддерживаемого формата на linux/amd64 в конечных ресурсных пределах. Это не все registries/platforms/formats/размеры и не универсальная проверка всех экосистем. Старые baseline/proofs/default AppModule и старое HOLD окружение сохраняются.

**SOURCE и controlled integration готовы; native запуск и deployment ещё не проверены.** Docker daemon недоступен: `Cannot connect ... unix:///Users/vsevolod/.docker/run/docker.sock`. Он не запускался/не перезапускался агентом. Существующий8080 не изменялся, live DB не мигрировались. Работа находится в dirty tree, stage/commit/branch/reset не выполнялись.

## Что действительно реализовано

1. Общая metadata inspection/acquisition через прежний scoped HTTPS gateway/auth transport без direct fallback, Docker socket и выполнения entrypoint исследуемого образа. Child manifest/config/layers/hash/diffIDs/platform закреплены и проверяются повторно; streamed gzip/tar validation, owned cleanup, archive rehash. Никакой подмены Node→nginx/Alpine identity.
2. Отдельные limits:128MiB compressed/layer,512MiB compressed total,544MiB delivered response-body bytes,64layers,512MiB expanded/layer,1GiB expanded total,100000entries,256MiB/file,1152MiB archive,2GiB logical scratch,180s acquisition. Это не literal wire/CONNECT/kernel metrics. Worker4GiB/no additional swap,CPU1/PIDs128,tmpfs2304MiB; stdout/report/component/count bounds остаются конечными.
3. Нормализация CVE/SBOM для закрытого enum apk/deb/rpm/npm/pypi/gem/gomod/cargo/maven/composer/nuget. Explicit OS families Alpine/Debian/Ubuntu/redhat/centos/rocky/alma/oracle/amazon. Фактическое inventory/OS evidence обязательны; missing/malformed/EOL/unknown не становятся checked0. Тип вне контракта fail-closed, не silently omitted. Java/offline DB ограничения не скрываются. Эта кодовая поддержка не является native certification каждого ecosystem/OS.
4. Public результаты остаются в archive JSON; legacy SQL enums/обычные legacy parsers не расширялись глобально. Original claim token/expiry/target/receipt authority, checkpoints, cancellation/reopen/retention сохранены. Config имеет отдельную explicit public composition; API и worker одинаково выбирают LOCAL trust helper при заданном публичном fingerprint, production default неизменён.
5. UI: manual canonical reference, fresh server eligibility, auth/checks/consent/POST, pinned status, public report parsers/ecosystem filters/reload. Public marker зависит от реального receipt, а не обслуживающего endpoint; legacy Alpine `edge` остаётся читаемым. Новый image-only module не активирует runtime/host/LLM.
6. Новая независимая qualification composition `dip-public-images` на127.0.0.1:8081: own volumes/networks/images/JWT/new accounts, fixed guarded resources, pre-start image/default-env validation, immutable image-ID start, local pinned Unix daemon, exact-name inventory before inspect, private build-context ignores, HOLD on uncertain mutation. Старые8080 accounts/reports/JWT/volumes не импортируются и не меняются. Автообновление pinned CVE release нового project не реализовано; истёкшая DB не обходит freshness guard. Existing LOCAL scheduler/refresher не должны управлять новым project.

## Независимые review

- `public-image-oci-final-review-20261018.md`: R1 mixed PAX/GNU ambiguity иR2 lossy ASCII устранены, добавлены red→green regressions; metric wording исправлен. Повторный verdict QUALIFIED APPROVE,63 socket-free tests. Native acceptance не выполнялась.
- `public-image-chain-review-20261018.md`: R1 loss of accepted checkpoint after late audit иR2 legacy/profile mislabelling исправлены. Runner сохраняет recovery authority; ledger дополнительно transactional consistency guard, допускающий только независимо доказанный current CVE expiry downgrade. Повторный scoped APPROVE,283 targeted results и независимые probes.
- `public-image-launcher-review-20261018.md`: исправлены4 findings pre-start inherited image authority, misleading-label legacy inspect, Dockerfile-specific ignore overrides, mutable daemon context. Повторный scoped offline APPROVE,42 tests и independent probes. Не реальное разрешение/свидетельство успешного daemon/native launch.

## Финальные проверки

Команды выполнялись на существующих установленных зависимостях, без установки/реального scanner/registry/старых proofs:

- API `pnpm test && pnpm exec tsc --noEmit`: **1176/1176 PASS**,0 fail/skip/cancel; typecheck PASS.
- UI `pnpm exec vitest run --maxWorkers=1`: **573/573 PASS**,26files;71.79s.
- `node --test scripts/test_public_image_stand.mjs scripts/test_local_stand.mjs scripts/test_refresh_local_cve.mjs scripts/test_schedule_local_cve.mjs`: **218/218 PASS**,0 fail/skip/cancel.
- `pnpm lint`, `pnpm typecheck`, API typecheck: PASS.
- `pnpm build`, `pnpm build:admin`: PASS; основной Vite bundle имеет прежнее предупреждение chunks>500kB.
- `node tests-e2e/public-image-api.mjs`: actual Chromium147/current UI/manual reference→eligibility→POST→real consumer/SQLite→Debian/npm/Secrets/config report→reload/legacy edge/owner fences PASS (~7.7s).0 pageerrors/external browser requests; cleanup verified. OCI/scanner outcomes контролируемые, HTTP не mocked; CVE DB/native/Compose не квалифицированы.
- `node --check tests-e2e/public-image-live.mjs` и`--self-test`: PASS; явный `nativeQualification:NOT_RUN`,0network/0accounts. Это подготовка, не native scan.
- Final `git diff --check`: PASS.

Один совместный тяжёлый API/UI прогон: UI572PASS/1FAIL в существующем C4 replay test. Без изменения теста отдельный файл53/53 и последовательный полныйUI573/573 прошли. Причина нестабильности не установлена и не объявлена исправленной. Первый полныйAPI до последних tar regressions1164/1164 также прошёл; не суммировать overlapping counts.

## Точный следующий внешний шаг

Запустить Docker Desktop (предоставить доступный локальный daemon). Затем выполнить **только новый isolated project**:

```sh
node scripts/public-image-stand.mjs up --build --isolated
node scripts/public-image-stand.mjs status
```

Первый запуск может собирать/скачивать образы и выделяет4GiB worker; localhost8081, отдельный browser context/new accounts. Команды подготовлены иoffline-reviewed, но пока **не выполнялись**. Не обходить HOLD или guard ради запуска. Нельзя считать запуск успешным до postflight реальных image/cgroup/tmpfs/network/DB/readiness проверок. СтарыйLOCAL launcher не использовать для этой composition.

После успешного postflight/qualification среды:

```sh
node tests-e2e/public-image-live.mjs --run-native
```

Это один настоящий Node22.14.0/Alpine3.21 image-only workflow, fixed8081, без credentials/target overrides/mocks/identity projection. Он создаёт только свои новые account/report, проверяет четыреchecks/identity/inventory/report/DB/reload/freshlogin, не фабрикует positive CVE. Unsupported/EOL/failed не дают proofPASS. Даже успешный одиночный smoke не подтверждает всеOS/ecosystems/negative матрицу: они остаются отдельной квалификацией.

## Flownix/spec disposition

Итог опубликован как **DIP-ARTF-547**; TASK2 после source-инкремента переведена в `blocked` с конкретным native/Docker blocker. Новых done или каскадных закрытий нет.

Full TASK2 не закрывается из source/control evidence. Существующие принятые14/16/21/39/40/41 не переоткрываются; TASK6 runtime/Linuxqualification остаётся отдельнымblocker, не prerequisite registry image scan. TASK27 provenance не снимается ручной UI waiver.

Подготовлен **полный** resulting DOC1v5 draft `public-image-doc1-proposal-20261018.md`:37requirements/46scenarios,23legacy requirements сохранены+14 optionalpublic,`validate_spec valid`. BaseSHA a04a8d75b7eef33c65da1d7beb5b0bad8e9fcd13594717b6e94a5340e8b9c1a4,proposalSHA c96391884463da0bcf9597fbb2b04ca167fe4048df05f69bc0d049ecb89c170f. Это локальный подготовленный draft; MCP delta не предложена/не applied, не awaiting human approval и не whole-task completion. При продолжении перечитать liveDOC1 и проверить base/drift перед propose/apply. DOC2/6 cancellation reconciliation тоже не считать выполненной автоматически. No-spec-impact декларация не использовалась.
