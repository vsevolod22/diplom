# Обычное развёртывание

Команды выполняются из корня `diplom` с установленными зависимостями.
Это интерфейс нового `scripts/deploy.mjs`, не обёртка старого lifecycle launcher.

## Текущая готовность — 07.11.2026

- Web `769d0de68b245b7c3a81af5a5cdfa0b6` опубликован штатным `web --apply`: `new-healthy`, lock released, без миграций. От первого journal до completion — **89,9 с**, не обещание мгновенных будущих выкладок.
- Доставлены frontend-коммиты `5e60471` и `de1d10e`: безопасный возврат из восстановления пароля, восстановление сохранённого чата при readiness-timeout, сохранение проверенных источников черновика, видимый применённый фильтр и исправления навигации. API/worker/gateways не обновлялись; прежний API-only `fd4122b0af8bbb2f526930b64cfebcfb`/schema5 не мигрировал в этом запуске.
- Capacity fix `1df2930`: исторический каталог сохраняет active32/archive16/total48, adapter — отдельные 48 слотов с резервированием до мутации. Полная проверка истории/custody/evidence/ref128 сохраняется; конечная ёмкость не означает бесконечное хранение. Синхронное чтение evidence проверяет прежний operation/lease deadline.
- Целевые проверки: новые history12/12, смежные custody/actual-adapter/recovery53/53, выбранные web-deploy4/4, syntax/scoped lint/diff-check PASS. Это не полный test suite.
- На опубликованном 8081 выполнен authenticated GET-only report → saved summary (4 русских абзаца) → chat (3 источника) → reload на375/1280:198 GET,0 POST,0 denied/pageErrors, DTO стабильны, overflow нет, browser закрыт, session file unchanged. Новая генерация, семантическая точность и исправление исторического chat HTTP502 этим не подтверждены.
- Перед правкой очищены только воспроизводимые host caches (76 705 792 allocated bytes) и4 неиспользуемых/необязательных `:local` aliases;123 retained refs и8 public peer IDs/images/epochs сохранены. Image bytes не удалялись; неоднозначно атрибутированный BuildKit cache оставлен. Базы/snapshots/unknown liabilities/CVE/baselines/evidence не удалялись. Локальные receipts: `test-results/cleanup-20261106-host.json`, `test-results/cleanup-20261106-aliases.jsonl`.
- Финальные записи в Flownix на момент завершения не приняты: MCP ответил `server shut down`. Итог сохранён здесь; не считать harness полностью завершённым после прерывания source/test lanes квотой агентов. Push и закрытие задач не выполнялись. Loopback8081 по-прежнему не публичный production.

### Исторический snapshot подготовки batch27 — 03.11.2026

Следующие статусы относятся к моменту подготовки и superseded текущей записью выше.

**Новый batch27 не развёрнут и native acceptance не получена.** Последний live baseline
по handoff координатора: API-only deployment `e412479434bb16f97b1d7e4043214eb2`,
history schema **4**, four-store preservation. Это атрибуция, не повторная live-проверка
документной lane. Наличие schema5-кода, offline PASS и завершённого harness work не меняет
версию live authority и не даёт release GO. Public production readiness не заявляется.

В source подготовлены полный citation contract 7650 bytes/source и 65536 aggregate,
held summary slot 69632 bytes/schema5, postcommit deadline guard и уточнённый chat UX.
Они требуют одной согласованной поставки, final frozen-source review, проверки migration/
recovery и отдельной bounded native acceptance. Текущий статус и короткий checklist —
[batch27 final spec handoff](batch27-final-spec-handoff.md); ранний
[batch27 acceptance и release checklist](batch27-acceptance-release.md) сохранён как
snapshot предыдущего run, его mapping blocker и CVE-null ограничение superseded ниже.

Ниже сохранён исторический app rollout TASK32. Его READY относится только к той попытке,
не к batch27, текущему history schema5 или универсальному восстановлению.

### Исторический TASK32 app rollout

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
Исторический auth-only пример выше не разрешает новый history schema4→5 переход:
для него действует отдельный prospective контракт batch27 ниже, без combined auth/
operations upgrade и без запуска до coordinator GO.
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
Универсальной recovery-команды нет; узкое историческое reconciliation ниже не восстанавливает сервисы или БД.
Prospective batch27 prestart continuation описано отдельно в конце документа: это не
разрешение применять его к старым attempts или к running/publication-uncertain фазам.
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

## Batch27: отдельный history4→5 переход — ещё не rollout

Source: `server/api/src/llm/history-store.ts`, `history-init.ts`,
`scripts/deploy-core.mjs`, `deploy-adapter-stores.mjs`, `deploy-adapter.mjs`.
Это описание подготовленного контракта, не инструкция исполнить миграцию сейчас.

- Constructor понимает3/4/5 без upgrade. Исторический `--migrate-summary-schema`
  остаётся ровно3→4. Новая `--migrate-history-v4-to-v5` — отдельное явное согласие,
  не auth `--migrate`, не reset/init и не автоматически chained3→5.
- Static existing-file migrator проверяет schema/integrity/FK/все retained records,
  меняет только user_version4→5 в FULL IMMEDIATE transaction; valid5 — проверенный
  no-op. Deploy helper не переигрывается на5 ради нового4→5 receipt.
- До actual migration writers остановлены; B0 остаётся сохранён. Независимая relation
  B0→B1 разрешает только version4→5 при одинаковых schema и всех typed rows/rowids;
  auth/ledger/quota неизменны. После неё before-api/after-api равны B1 без waiver.
- Initial history transition ограничен API и optional web, без combined auth или
  operations upgrade. На5 обычный5→5 update не повторяет migration. Старый4 binary,
  header downgrade5→4 и восстановление stale B0/B1 не являются rollback этого scope.
- Ordinary schema4 summary GET поддержан новым reader, но held summary generation
  требует5. Наличие source flag не означает, что live e412… уже мигрировал.

Held slot удерживает69632 bytes до quota/send вместо прежней probe-with-rollback;
response65536/global64+2MiB/owner8+256KiB/DB8MiB/sidecars16MiB/free128MiB не увеличены.
GET не reclaim expired slots и не мигрирует. Только explicit same-scope acquisition
может reclaim expiry; после dispatch failure/unknown slot и accounting не становятся
refund. Equal-size FULL commit предшествует HTTP success; optional shrink failure
оставляет readable padded result. Абсолютный original generation deadline проверяется
после commit/finalization и прямо перед публикацией после durable reread. Late POST
может отказать, хотя committed result затем доступен fresh authorized GET без resend.
Это не гарантия успеха при произвольной corruption/power loss или extra writer.

## Batch27: prospective OS lease и узкий prestart continuation

Повторная инспекция03.11.2026 подтверждает wiring в source: CLI `deploy.mjs`
принимает `recover --audit` и exact `--checkpoint` для apply; app/recover apply
подключают OS supervisor. Core вызывает adapter `planRecovery/applyRecovery`,
а `checkpointPrestart` записывается после migration proof. Это supersedes раннее
наблюдение промежуточного unwired CLI, но **не доказывает independently qualified
end-to-end recovery** и не разрешает запуск. В run `15f1404e-40ec-460d-a335-b33b7ee9a3bd`
координатор заморозил source626 для независимых final tests/review. Docs lane сверила
SHA256 deploy CLI/adapter/authority/supervisor с626; это не результат всей квалификации.
Старое `recover:false` обозначает отсутствие общего recovery; narrow capability
не делает все стадии восстанавливаемыми. Перед использованием нужен final source
snapshot, независимые tests/review и отдельный coordinator GO.

Prospective контракт:

1. Новый supervisor держит OS flock через общий inherited open-file description
   supervisor/coordinator. Сохраняется inode lock-файла; файл не удаляется для unlock.
   Истечение timestamp/lease, исчезновение PID или read-only free observation сами
   по себе не разрешают adoption. Recovery требует собственной эксклюзивной OS lease
   после освобождения старой, exact lock identity и другой supervisor session.
2. Только заранее записанные protected checkpoint v3, authority и settled engine
   journal от исходной попытки. Source/entrypoints/config/recipes/immutable images,
   daemon/volumes/namespace/service control identities и sealed evidence совпадают.
   Нельзя задним числом создавать checkpoint для old attempts или считать JSON
   `preserved:true` авторитетным proof. Raw env/secrets/private payload не публикуются.
3. Единственный prospective positive branch — `v5-committed-prestart`: migration
   completion и helper removal доказаны, B0/B1 sealed, все web/API/worker stopped,
   нет pending dispatch, start/restore/publication submission. На apply независимо
   пересчитывается4→5 relation, новый current four-store snapshot должен равняться B1.
   Read-only plan сам не читает current stores и не заменяет этот gate.
4. Только forward suffix worker→readiness→fresh before-api equality→candidate API→
   after-api equality→preservation→web→health→publication→complete/archive. Нет повторной
   migration/build, старта old4 или overwrite прежних B0/B1. Новое evidence отдельно.
5. Unknown migration/helper, writer-start submission, running writers/web, publication
   uncertainty, changed evidence/identity, повторная recovery попытка — HOLD до
   отдельно проверенной процедуры. Нельзя применять B1 как restore image после новых
   пользовательских записей. Prestart recovery не решает late-phase failures.
6. Source626 сохраняет existing pinned CVE binding при reconstruction candidate model
   (`deploy-adapter.mjs`, `readRecovery`), а не требует `config.profile.cve===null`.
   Это supersedes прежнее промежуточное ограничение, но не разрешает refresh/provision/
   config transition и не доказывает end-to-end qualification pinned-CVE профиля.

Нужны доказательства single adopter/живого старого executor, crash/ack-loss и refusal
всех неподдержанных фаз; operational late-failure решение остаётся отдельным gate.
DIP-ARTF-607/610 квалифицируют предыдущую version-only migration, не этот новый path.
Новый test-lane DIP-ARTF-620 сообщает27/27 supervisor/authority/early-negative tests,
87/87 synthetic migration, final1/1 actual-adapter synthetic4→5 и2/2 migration-failure
HOLD. Полный adapter suite остановлен timeout60s — НЕ whole-suite PASS.
Source626 дополнительно сообщает38/38 scoped checks,2/2 focused adapters,4 finite CLI
cases и1/1 actual SQLite/flock recovery smoke с recreation adapter в одном Node process.
Это не killed/restarted-process positive. Полный persisted cross-process recovery,
valid-checkpoint adversarial matrix и pinned-CVE qualification переданы final infra_tests;
их окончательный результат требуется отдельно. Early rejection fixtures не заменяют
эти проверки. Ни эти тесты, ни live действия docs lane не запускала.
Контракт summary/citation меняет policy identity: historical summary bytes preservation
и current-policy GET404 проверяются отдельно. Qualified deployment B0/B1 original-store
preservation — отдельное достаточное evidence в своём scope; новый historical-row endpoint
не требуется. Exact404 `LLM_SUMMARY_MISSING` — current miss, не proof старой строки или
её удаления. Не обходить404 и не переиспользовать spent markers; новая separately authorized
summary1→chat1 с fresh paid consent — новая acceptance, не исправление истории.
Текущие blockers и checklist — в [final handoff](batch27-final-spec-handoff.md).
