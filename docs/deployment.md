# Обычное развёртывание

Команды выполняются из корня `diplom` с установленными зависимостями.
Это интерфейс нового `scripts/deploy.mjs`, не обёртка старого lifecycle launcher.

## Текущая готовность

По actual evidence sole a7 в TASK32 app rollout **READY**:
`e8746d1a298cd49ebe42f3d729c167c5`, 505.5s, `new-healthy`, lock released,
HTTP8081 root200/anonymous auth-me401; опубликован `public-images-v2`.
Auth A2→A3: две квалификации constructor на копии, actual after-API fingerprint
совпал с expected; четыре stores сохранены с разрешённым additive auth изменением,
ledger/history/quota, включая liabilities, неизменны. Web открыт после preservation receipt.
Это первая успешная actual app-квалификация, не универсальная recovery/web-only/native
приёмка, не проверка нового AI token или paid AI. GET-only smoke учитывается отдельно.
Mandatory build/guards/health пройдены; optional --verify/fullsuite не запускались.
Исторический offline PASS 15/15 за 21.05s не предотвратил последующие actual отказы:
STOP_OUTPUT_INVALID, HELPER_CONTROL_CHANGED и HELPER_STOP_OUTPUT сохранены в TASK32.
Их OLD restore/reconciliation не означали новый rollout; неизвестный stop stdout не восстановлен.
Incident415 ранее архивирован в
`exact-recovery-compensations/restored-41522be2994d3a54fd5cd010ac26d3d4`
с incident и обоими locks. Прежние «OLD не обновлён» относятся к тем попыткам, не к текущему READY.
Docs lane runtime/git не проверяла. Public host/TLS/DR остаются отдельными gates;
каждый следующий rollout требует нового GO и свежих checks.

## План и статус

```sh
pnpm deploy:status
pnpm deploy:web
pnpm deploy:app --services web,api
```

Без `--apply` web/app выполняют read-only preflight и возвращают план:
это не сборка, резервирование или разрешение deploy. `--plan` и `--dry-run`
явно выбирают тот же режим; совмещать их с `--apply` нельзя.
`status` читает readiness/lock, не снимает HOLD. Ошибка чтения — не READY.
Даже успешный план не гарантирует, что состояние останется прежним до apply.

## Web отдельно

После review/qualification GO, проверки совместимости и отсутствия HOLD:

```sh
pnpm deploy:web --apply
```

Область изменения — только `web`, без API/worker/gateways, stores и auth migration.
Новый UI требует совместимого backend; старый auth A2 может блокировать web-only.
Не обходить compatibility check: сначала нужен согласованный app upgrade.

## App и явная миграция

`app` требует точный `--services`; adapter требует включить `api`.
Допустимы только `web`, `api`, `worker`, `egress`, `llm-egress`, `openai-egress`.
Добавлять worker/gateways нужно лишь если они входят в проверенный upgrade scope,
а не для каждого обновления UI. Другие сервисы CLI не подразумевает.
Различайте `services` (обновляемые images) и `interruptedServices`: app временно
останавливает также `web/api/worker`; невыбранные web/worker возобновляются с прежними
container IDs. Изменение runtime selection требует всех шести targets; topology
networks/volumes менять этим CLI нельзя.

Для первоначального согласованного upgrade **всех этих шести сервисов**, если
план требует миграции, после qualification/rollout GO и штатного разрешения HOLD:

```sh
pnpm deploy:app --services web,api,worker,egress,llm-egress,openai-egress --upgrade-operations --migrate
pnpm deploy:app --services web,api,worker,egress,llm-egress,openai-egress --upgrade-operations --migrate --apply
```

`--upgrade-operations` явно выбирает `public-images-v2` только для app со всеми шестью services.
Обычные последующие обновления сохраняют operations selection без этого флага;
он не разрешает неявную смену provider/config или fallback и не доказывает live rollout.
Первая команда — только план. `--migrate` — явное app-only согласие, не команда
самостоятельного запуска миграции и не разрешение reset/пересоздания БД.
При отсутствии требуемой миграции не добавляйте флаг механически.
Каждый app rollout, даже без миграции, ждёт idle, сохраняет recovery record,
закрывает admissions/останавливает writers, делает snapshot четырёх stores и
проверяет auth/ledger/history/quota на копиях. `--migrate` разрешает требуемое
изменение auth A2→A3 при старте нового API, а не отдельный live-migrate шаг.
После worker и API сравниваются stores, затем открывается web и публикуется receipt.
Этот порядок квалифицирован для указанного выше app rollout, не для любого будущего запуска.

## Проверки и ошибки

Обычный pipeline предусматривает compilation/build, config и bounded health,
не полный test suite. `--verify` в текущем adapter повторно проверяет стабильность
source/config/OLD после validation; это не запуск Sol suites и не native acceptance.
`deploy:check` не введён.
Для app `--drain-timeout-ms` задаёт ожидание idle: 1..300000 ms, default 30000.
Adapter ограничивает единым бюджетом peer inspections, drain probe и sleep,
также учитывая оставшиеся operation/lease deadlines. Core ждёт завершения adapter
без конкурирующего timer/Promise.race и не освобождает lease при активном probe.
Увеличение времени не разрешает отменять чужую работу или обходить fencing.

CLI выдаёт безопасный JSON; exit 0 — успех либо план, 1 — отказ, 2 — занятый lock.
Смотрите `phase`, `code`, `state`, `lock`, `rollback`, `nextAction` у отказа.
- `DEPLOY_LOCKED`: остановиться; существующий lock не удалять, даже «старый».
- `DEPLOY_ADAPTER` / `DEPLOY_UNSUPPORTED`: проверить контракт/scope, не обходить guard.
- `DEPLOY_COMPATIBILITY`: согласовать app upgrade либо совместимый UI.
- `DEPLOY_MIGRATION_REQUIRED`: проверить scope, snapshot/recovery и явное согласие.
- Build/config/drain отказ: устранить причину; повтор допустим лишь после проверки
  отсутствия retained lock и неопределённого результата предыдущей операции.
- `recovery-required`, `publication-uncertain` или retained lock: сохранить journal/receipts и передать
  оператору для проверки точных контейнеров и БД; не запускать apply повторно.

## Что не происходит автоматически

Нет снятия чужого HOLD, очистки volumes/history/retained OLD images, восстановления БД назад,
настройки домена/TLS/mail, установки ключей или платных AI-проверок.
Не выводите env, credentials или сырые container configs при диагностике.
Ограниченный web rollback пересоздаёт только web из retained OLD image/recipe,
не восстанавливает прежний container ID; требует settled dispatch, проверенных
границ и health. Неизвестный dispatch или начатая publication исключают auto rollback.
App после попытки fencing сохраняет HOLD при отказе даже без миграции.
Универсальной recovery-команды нет; узкое reconciliation ниже не восстанавливает сервисы или БД.
Наличие команды, успешная сборка и план не являются live/native acceptance.

## Reconciliation уже восстановленного OLD adapter attempt

`scripts/deploy-reconcile-web.mjs` завершает только проверенное восстановление, не выполняет его.
Три отдельные пары команд, без автоматического выбора или fallback:
- `check` / `apply`: остановлен только web, same OLD web уже восстановлен; backend epochs неизменны.
- `check-fenced-writers` / `apply-fenced-writers`: три writers восстановлены, helper clean retired,
  host export пуст; helper мог читать stores — это не доказательство отсутствия чтения БД.
- `check-exported-writers` / `apply-exported-writers`: сохранены четыре DB exports и два manifests;
  проверяются bytes/hash и integrity/logical fingerprints сохранённых копий, не live DB.
Для всех: точный journal без qualification/switch/migration/publication, historical intent отдельно
от current source, validated OLD identities/config/epochs, retained refs и health обязательны.
`check* --attempt '<id>' --historical-intent '<sha256>'` не снимает lock.
После независимого review и operator GO соответствующий `apply*` получает те же аргументы,
затем `--review '<review>' --source '<source>'` и ack: `--ack-reconcile-restored-web`,
`--ack-reconcile-restored-writers` либо `--ack-reconcile-exported-writers` соответственно.
Apply сохраняет evidence, пишет complete v2 `old-restored`, архивирует original lock и guard последним.
`WEB_ATTEMPT_RECONCILED` не означает новый deploy, completed snapshot или post-restart DB equality.
Неизвестный/частичный layout или отказ: HOLD, без retry/resume/ручного unlock; lifecycle здесь нет.

## Archive-only после подтверждённого restored-v6

`scripts/deploy-reconcile-restored.mjs` поддерживает только точный restored-v6 layout
с завершённым restore и его receipts; это не общий recovery, restore или deploy.
Нужны сохранённый historical restore source, проверенные audit/restore-review bindings,
независимое review актуального check и отдельный operator GO. Порядок флагов строгий.
Ниже шаблоны: замените placeholders проверенными значениями; реальные hashes не приведены.

```sh
node scripts/deploy-reconcile-restored.mjs check --audit '<audit-id>' --restore-review '<restore-review>' --restore-entry 'scripts/public-images-v6-restore-<id>.mjs'
node scripts/deploy-reconcile-restored.mjs apply --audit '<audit-id>' --restore-review '<restore-review>' --restore-entry 'scripts/public-images-v6-restore-<id>.mjs' --review '<check-review>' --source '<check-source>' --ack-archive-only
```

`check` читает evidence, source, Docker inventory и HTTP health, не изменяя lifecycle
или архив. Для `apply` берутся именно проверенные `review`/`source` из этого check;
apply повторяет проверки и сохраняет evidence при переносе incident и operation lock.
Отдельный archive guard создаётся до переносов и архивируется последним.
Нет build/switch/restart, migration, чтения live stores или содержимого secret-файлов;
сохранность stores опирается на прежние restore receipts, не на новое сравнение БД.
Успешный итог — `RESTORED_INCIDENT_ARCHIVED`, не rollout/native qualification.
Любой отказ: **остановиться, без retry/resume и ручного удаления guards**;
частичное архивирование требует отдельного review/operator решения. Уже архивированный
incident415 повторно не запускать. Не печатать env, секреты или raw container configs.

Отдельная offline проверка модуля (не часть обычного deploy и не live acceptance):

```sh
node --experimental-vm-modules --test scripts/test_deploy_reconcile_restored.mjs
```
