# Очистка Docker диплома — 09.11.2026

## Последующее исправление и выкладка
Исторический remount blocker ниже устранён отдельным source increment в `public-image-stand.mjs`: сравнение исторического dev ослаблено только у completed/hash-validated history; current state/archive filesystem, inode/uid/mode/schema/hash остаются точными. Четыре shared recovery validators по умолчанию сохраняют exact equality; active capture/lock/recovery fences не менялись, записи не переписаны.20new/relatedtests+4existingactivefenceregressionsPASS; H6v13 run `a7dd9b92-d253-4c78-bd1f-45728922416d` получил четыре независимых Sol review/test reports и final source GO. Actual history+acquireLock/releasePASS.

После этого normal web+api apply завершён `dcaa44be097ac42e33e568a7e7c86c6c`, new-healthy/lockreleased, completedAt2026-11-09T11:15:03.773Z, без migration/historyMigration/operationsupgrade. Root200/auth401/statusready-unlocked. Один реальный UI chat POST200, ответ безreload ипослеreloadPASS,0pageerrors/0overflow375. Предыдущий текст о НЕ выполненном apply — исторический статус cleanup, а не текущая блокировка.

## Разрешение и результат
Владелец явно согласился пожертвовать старыми образами отката ради места. Удаление только старых положительно атрибутированных `dip-public-images` images; текущие7pinned image IDs и образы8существующих peers исключены. Ни глобального prune, ни reset Docker.raw, ни изменения8080.

- План:108старых image IDs /148retained tag obligations. Сумма логических размеров15.43GB — НЕ обещание physical reclaim из-за shared layers.
- Выполнение: **96images удалены**,12refused (`multiple repositories`), без `force`, удаления контейнеров или volumes. Удаление по неизменяемому image ID; mutable-tag TOCTOU из первого review исправлен до dispatch.
- Явный отказ от прежних image-custody obligations опубликован ДО удаления: `.local-public-images/image-retirements-v1/1791030a5a9eb22910959de240f02663.json`, owner0600. Старые receipts, snapshots, incidents и borrowed provenance не переписывались. Если удаление отказало, waiver не означает, что image физически исчез.
- Затем121точно атрибутированная запись кэша удалена прежним guarded cache operator; Docker reported1.402GB. Не общий builder/system/volume prune. Own peers/images/epochs и4905state metadata entries не изменились этой cache-only операцией.
- Измеренный allocated размер Docker.raw: **31GiB →28GiB**. Финальный df показывает40GiB available; свободное место Mac меняется также от фоновых процессов, поэтому весь прирост не приписывается этой операции.
- Docker census133→37images; final image size24.04GB, separate build cache7.317GB. Не суммировать logical/shared показатели как физическую занятость. Остаток включает рабочие, общие, чужие и консервативно оставленные multi-tag образы.
- Контейнеры32, running9, volumes31/104.5MB — не удалялись. Protected own runtime/pins/volume-name baseline до/после совпал. Содержимое БД не читалось/не менялось cleanup operator. Postflight ready=true/locked=false, HTTP8081root200.

Private ignored receipts/source: `test-results/retire-images-20261109/`, `test-results/cleanup-20261109-after-retirement/`. Нельзя сбрасывать plan/submission markers и повторять apply вслепую.

## Проверки и управление
DIP-HRNS-6v13 run `64810513-5b88-4c6a-ba51-2b93f0d96d23` **completed**: четыре независимых Sol6.1 reviewers/tester, затем final review. Source GO narrowly image-only;15/15new unit tests, focused borrowed-origin/schema/FS controls, syntax checks. В первом topology review был реальный blocker deletion by mutable tags; fixed immutableID/no-force и отдельно re-reviewed. Последующий image-only lock helper получил отдельный static GO того же final reviewer.

New `scripts/deploy-image-retirements.mjs` аутентифицирует waiver по точному historical name/tag/image/origin, owner/mode/no-follow/single-link и freshness directory/file fences. `captureBuildHistory` сначала валидирует ВСЮ историческую provenance/borrowed graph, затем исключает waived live-image obligations. Legacy engine verification пропускает только exact authenticated retired tags. Это не сброс records/accounting или разрешение потерять текущие images.

**Ограничение:** retirement освобождает image disk custody, но НЕ снимает неизменённые исторические capacity ceilings. Достижение256исторических refs всё ещё отдельный будущий admission blocker, даже при меньшем live set; caps не повышались.

## Найденный отдельный host-remount blocker
До image deletion обычный read-only app preflight уже отказывал. Finite диагностика установила: все9archive roots имеют прежние inode/names, но исторический `st_dev` отличается от текущего. `archiveRootMatches` теперь проверяет current archive/state filesystem equality, сохраняя recorded inode/membership и receipt digests; старый transient mount device number не persistent volume identity. После этого normal read-only web+api plan PASS (migrationfalse/historyMigrationnone).

**Однако фактический lifecycle lock остаётся заблокирован исторической `assertReconciliationHistory`:** старые redeploy completion file identities также сохраняют прежний st_dev (`public-image-stand.mjs:1379`). Этот lifecycle guard НЕ ослаблялся и НЕ обходился для deployment. Cleanup использовал отдельно review-нутый image-only lock — ту же атомарную `.operation.lock` exclusion с проверкой всех4recoverybarriers, ownership/dev/inode/mode/emptydir, fsync и guarded release. Он не запускает/останавливает services и не принимает старый recovery за завершённый.

**Новой выкладки чата в этой операции НЕ было.** Для app apply нужно отдельно квалифицировать remount-compatible historical identity validation. Рабочий сайт200 не означает доставку37b120f или исправление live chat. DB/sessions/quotas/UNKNOWN и retained backup evidence сохранены. Имеющиеся незакоммиченные source changes не сбрасывались и не добавлялись массово в Git.
