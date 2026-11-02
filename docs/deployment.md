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
не live qualification или native acceptance. HOLD ниже не изменён.
Commit blocker по handoff: prerequisites ещё не закоммичены; пакет из 9 файлов
не самодостаточен относительно HEAD и не готов как изолированный standalone commit.
Git-состояние в этой docs lane не проверялось и не менялось.
По handoff координатора старый сайт UP после incident415, но HOLD сохранён.
Здесь runtime не проверялся. Пока HOLD не разрешён штатно и нет rollout GO,
**не выполнять команды с `--apply`** и не обходить отказ старым launcher.

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
pnpm deploy:app --services web,api,worker,egress,llm-egress,openai-egress --migrate
pnpm deploy:app --services web,api,worker,egress,llm-egress,openai-egress --migrate --apply
```

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
