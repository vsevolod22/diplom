# Public8081 recovery: READY — 22.10.2026

## Фактический результат

Координатор выполнил один reviewed **`continue-current-api`**, получил **READY / exit0** и подтвердил сохранность accounts, reports, JWT, history и quota: четыре SQLite stores плюс JWT. Это завершает recovery HOLD из [status 21.10](public-product-status-20261021.md) и [исторического handoff](public-product-handoff-20261021.md); их старые команды не являются текущими инструкциями.

Audit: `deploy-8d83a8806715c2f0fa575efedee1b0af`. Успешный single-use route: `check-current-api` → `continue-current-api`; consumed review token: `718f045ccdc8c33ec7805345d64525451b9b02eb222a23c459f57e4333d41aab`. Это запись выполненной операции, **не команда для повторного запуска**.

Восстановление runtime не означает приёмку всего продукта. **Public provider key отсутствует; реальная provider generation здесь не проверена и не принята.** Catalog/model metadata, READY и offline tests не являются generation PASS. Native browser/scanner/runtime-проверки других исполнителей фиксируются отдельно.

## Краткая хронология и причины

| Этап | Установленный факт / граница знания |
| --- | --- |
| Исходный build HOLD | Первичная причина build exit1 не сохранена и остаётся неизвестной. Перестановка Docker Mounts воспроизведена как order-only drift; нормализация сохраняет все authority fields, но не доказывает единственность исторической причины. |
| Первый reviewed current-build continuation | HOLD initialize: Engine опустил declaration `ReadOnly:false` при observed `RW:true`. Validator исправлен только для отсутствующего own property либо явного false; true/null/string и readonly mount отвергаются. |
| Created-initializer continuation | Был намеренно отменён после retirement точного never-started stale helper, до новых pins. Это cancellation, не доказанный build defect. Старые evidence сохранены. |
| Current rebuild | Четыре актуальных images построены; новый initializer exited1: подтверждён `ENOENT mkdir /tmp/tsx-65532`. Все новые helpers получили точный `TMPDIR=/backup` в существующем writable tmpfs; Env validator обновлён строго. Неисправный helper не перезапускался. |
| Init-exit completion | Native history/quota initialization завершилась; новые worker и llm-egress запущены, API/web оставались stopped. Ранний HOLD ready-worker не сохранил исходную exception; её историческая причина отдельно не утверждается. |
| Admission-only attempt | Сохранён four-store snapshot, затем HOLD ready-worker. Read-only воспроизведение точного shared `d → ready` пути установило launcher root: дробный timeout от `performance.now()` вызывает native `execFile` `ERR_OUT_OF_RANGE` **до Docker dispatch**; прежний catch скрывал причину. |
| Final API completion | Оба shared `d` boundaries используют finite positive `Math.floor` timeout, никогда 0. Новый exact consumed-prefix route сохранил существующие stores, не делал build/init/restart worker/gateway; API допущен после проверок, web — последним. Actual READY / exit0. |

## Preservation и read-only диагностика

- Диагностика не повторяла lifecycle: production readiness body и shared wrapper воспроизведены в памяти с deny-mutation runner. Проверены 98 retained proofs и control/epoch семи peers. Дробный timeout воспроизвёл native validation failure; тот же путь с integer timeout прошёл JSON parsing и точное ready/manifest/bundle сравнение.
- Image source остался неизменным после успешного rebuild. Host-only timeout/continuation fixes включены в новый reviewed execution closure из 16 модулей; candidate immutable pins проверены фактическим image inspect. Недоступные original API/web/worker images остались retire-only, без сертификации отсутствующей metadata и без start/exec originals.
- Snapshot helpers: validated candidate API image, network-none, два readonly public volume mounts, fixed program, `TMPDIR=/backup`; без key reads. Native initializer выполнялся раньше отдельным разрешённым шагом, **не повторялся** в final completion.
- Original, continued, initialize-current, rebuild-current и init-exit-current core baselines проверены. Final route дополнительно проверил сохранённый `admit-current/fenced` four-store export: manifest/byte integrity, typed schema/data fingerprints, native empty LLM tables и metadata.
- Свежий fenced snapshot обязан совпасть с последним сохранённым baseline **по всем четырём stores**, включая history incarnation и quota metadata, а не только по признаку empty. Before-api и after-api snapshots сравниваются до web admission; чужие/nonempty/drifting данные не удаляются и не переинициализируются.
- У десяти старых advisory SQLite SHM файлов наблюдался только drift mtime/ctime при совпадающих SHA и остальных identity fields. Исключение ограничено этими historical paths; main/WAL остаются строгими, новые execution proofs фиксируют текущую metadata. Evidence не переписывались.
- Все прежние intents/checkpoints/backups сохранены; успешный `api-current` архивирует весь operation evidence. Нет generic unlock/retry/rollback/delete-backups. Protected8080, dip-local-full, `.local-auth` и retained holders этой recovery работой не изменялись.
- Readiness failures теперь сохраняют конечные category/origin и allowlisted source frames, без raw error/logs/Env/provider payload и без чтения error getters.

## Валидация

| Проверка | Результат |
| --- | --- |
| До timeout fix: полный launcher suite | 198/198 PASS; это исторический результат, не обнаруживший native fractional-timeout defect. |
| После fix: targeted API-completion | 13 PASS: success, exact-prefix refusals, metadata/core/LLM drift, before/after API, readiness failure и replay. |
| Native timeout regressions | 2 PASS: настоящий execFile, fractional clock, normal и continuation shared boundaries, отказ zero/nonfinite budgets. |
| Повторные admission regressions | 3 PASS. |
| **Финальный полный `node --test scripts/test_public_llm_stand.mjs`** | **213/213 PASS**, 0 fail/cancelled/skipped; около 23 минут. Включает перечисленные targeted tests, не суммируется с ними. |
| **Финальный `node --test scripts/test_public_cve_llm_integration.mjs`** | **10/10 PASS**, 0 fail/cancelled/skipped. |
| Syntax / git diff whitespace checks после code fix | PASS. |

Тесты используют disposable fixtures, native SQLite и native child-process seams; они не заменяют actual deployment или browser/provider qualification. В финальном документационном шаге production scripts, images и runtime не менялись; UI/API suites и native qualification повторно не запускались, product code не затронут.

## Дальнейшая эксплуатация

Штатный entrypoint — `scripts/public-image-stand.mjs`: `status` для обычной проверки; `up` учитывает persisted seven-service LLM binding и относится к отдельному maintenance решению, **не требуется ради этой записи READY**. Не повторять consumed recovery routes/tokens и не возвращаться к историческим six-service recovery инструкциям. README/status reconciliation, Git и отдельное согласование cleanup ведёт координатор; этот документ не разрешает удаление images, containers, holders или backups.
