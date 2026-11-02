# Обычное развёртывание

Команды выполняются из корня `diplom` с установленными зависимостями.
Это интерфейс нового `scripts/deploy.mjs`, не обёртка старого lifecycle launcher.

## Текущая готовность

CLI/core и конкретный Docker adapter реализуют web/app switch, сохранительные
проверки и publication. Source capability `applyWeb/applyApp=true` не равна
live-квалификации: `liveQualified=false`.
По финальному handoff координатора Sol actual-adapter focused suite на final source
после drain clamp: **offline PASS 15/15 за 21.05s**, без edits во время финального теста.
Snapshot bug исправлен, reviewer fixes selection/web restore приняты;
drain fix CLOSED: scoped GO, findings нет. Это source/offline acceptance,
не live qualification или native acceptance нового deployment engine.
По handoff координатора sole a7 завершил archive-only incident415: SUCCESS после
независимого review и четырёх focused tests. Архив:
`exact-recovery-compensations/restored-41522be2994d3a54fd5cd010ac26d3d4`.
В нём сохранены `incident`, `operation.lock`, `archive-operation.lock`, `archived-restored.json`.
Активные guards отсутствуют; наблюдавшиеся HTTP-коды — root200/auth401.
Это завершение архивирования: **старый deployment не обновлён**, миграция не выполнена.
Эта docs lane runtime и git не проверяла; запись не утверждает готовность всего сайта.
Новый rollout требует отдельного GO и свежих checks; снятие прежнего HOLD его не разрешает.

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
Это source-порядок; реальная сохранность ещё требует независимой приёмки.

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
Общей recovery-команды нет; требуется отдельное операторское recovery-решение.
Наличие команды, успешная сборка и план не являются live/native acceptance.

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
