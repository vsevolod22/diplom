# Public product: фактический итог 21.10.2026

> **Историческая точка HOLD, заменена текущим READY:** public8081 восстановлен, HTTP200, 7 сервисов/6 сетей, four-store preservation завершена. Актуальный итог: [public-recovery-ready-20261022.md](public-recovery-ready-20261022.md), native scan/browser evidence: [attempt2](public8081launch-20261022.attempt2.md). Старые команды/требования продолжения ниже сохранены как история и не являются текущими инструкциями. Provider key по-прежнему отсутствует; full smoke safety guard остаётся незакрытым.

Это продолжение `public-product-handoff-20261021.md`, а не приёмка работающего продукта. Исторические proofs сохраняют свои даты.

## Runtime и сохранность

- Последняя HTTP-проверка: **8081 HTTP000**, **8080 HTTP200**. Защищённые старые окружения, keys/env и retained holders не изменялись.
- Audit: `deploy-8d83a8806715c2f0fa575efedee1b0af`. Original fenced backups и lock сохранены, ничего не prune/reset/clean/revert.
- Первый checker вернул другой token. Независимо воспроизведён order-only drift Docker `Mounts`; старый полный manifest не был durable, поэтому единственность причины исторического drift не заявляется.
- Исправлена сортировка копии Mounts по Destination, все authority fields сохранены. Closure15/43 edges и 29 targeted regressions независимо PASS; четыре последовательных checker дали `a0faa43c35c127fa746f8a9e715ac1301cfd80427c6b2cbc14870f1b0e373ab7`.
- Выполнен **один** `continue-current-build` с этим reviewed token и обоими acknowledgements. Он завершился **exit1 / HOLD phase=initialize**. Никаких повторных lifecycle submissions после отказа не было.
- Mandatory network-none current-store/original-backup comparison завершился до build/init. Candidate pins семисервисные; четыре builds завершились. Original worker не запускался и остаётся retire-only.
- Новый initializer `dip-public-images-llm-8d83a8806715c2f0fa575efedee1b0af-continued-initialize`, ID `8ac5fd9616bec19db55e8832700f7c777daef65f067dc4bd365cf0a8dfb8fec6`, image `sha256:62aecce04965c159ccd8aae03b1b62e0cfcdca557021f1a75fbf3164b8e8cc3a`: **created, never started**, PID0, zero start/finish epochs. Его default exitCode0 не является successful initialization.
- Конкретный failing predicate: Engine опустил declaration `ReadOnly:false` у writable `/auth`, materialized `RW:true`; прежний validator требовал явное false. Source исправлен: только absent own property или false, observed RWtrue обязателен; true/null/string/readonly negatives отклоняются до start. Независимо 6/6 regression PASS.
- Эта source-поправка **не** разрешает ручной start/retry. Native initialization, before-api/after-api four-store comparison, application replacement, persisted LLM binding и web admission **не завершены**. Прежние API/worker/web остаются stopped. 7services/6networks ещё не runtime PASS.

## Следующее lifecycle действие требует нового reviewed пути

**Старый check-current-build/continue-current-build теперь неприменим:** intent/checkpoint/candidate/helper уже записаны. Старые tokens не использовать. Не удалять lock/helper, не применять исторический recovery.

Нужен отдельно согласованный **created-initializer-only continuation design**: exact ID/never-started state/image/authority; original и continued backup integrity; current source closure и immutable candidate pins; preservation до любых новых изменений; original worker retire-only; four-store comparison и web-last. После backend sanitizer fix текущий candidate API **устарел**: нельзя выдавать его за актуальный source. Новый reviewed путь должен явно включить безопасный current candidate build и обращение только с этим never-started helper, сохранив evidence. Такой путь в этой сессии **не реализован и не выполнялся**. Это точный operational blocker, не причина обходить HOLD.

## LLM

Использована существующая summary/chat система, второй чат не создавался. Source profile: OpenRouter `xingchen-agi/xing4.0-29b-a4b:free` → `phala`, zero-price/privacy/no-fallback. Catalog metadata не является generation proof.

Public key отсутствует. Безопасный ввод владельцем вне Git: `python3 scripts/public-llm-config.py --set-key` — hidden local TTY. Не вводить ключ в чат/argv/Vite/logs; старые credentials не искать. После восстановления нужны документированные stdin→network-none initializer→UID65532 API-only readonly key volume provisioning/activation и настоящий browser smoke с явным request-scoped consent, двумя последовательными сообщениями, history reload/fresh login и foreign denial.

Реальных browser→provider сообщений **0**. **Чат как генерация не работает/не принят.** Adapter `stream=false`; NDJSON доставляет завершённый проверенный ответ, не native token streaming.

Дополнительно исправлен найденный review P2: quoted credential-labelled JSON/KV теперь отклоняется bounded sanitizer до question/decision mutation/provider construction; unsafe reply не публикуется. Это не universal DLP и не native provider test.

## Browser и CVE

- Новый guarded `tests-e2e/public-product-live.mjs` подготовлен для настоящего8081 workflow: disposable accounts, Node/Debian, eligibility/consent, actual scan/report/pages/filters/history/login, ownership, missing-key boundary и cancel subsets. **Native запуск не выполнен из-за HOLD**; offline tests не заменяют browser/scanner acceptance.
- Только после отдельного GO и runtime восстановления: `node tests-e2e/public-product-live.mjs --run --ack-coordinator-go --ack-no-key-activation`. Во время запуска key activation запрещена. Provider generation остаётся BLOCKED; cancel race/ненаблюдаемые subsets — INCONCLUSIVE. Не запускать при нынешнем HOLD.
- Public v2 CVE prepare/migration/fresh activation выполнены ранее. Последний confirmed manifest `sha256:5903d201b3dc68dda334b9a9397ed51bd7956d834f43ab4edae6844a18912ced`, UpdatedAt `2026-10-20T19:12:26.430296739Z`. Текущая runtime freshness не перепроверена при HOLD. Local operator signature не Aqua signature.
- Post-LLM actual refresh/four-store preservation и отдельный public scheduler **не выполнены**. Scheduler install не использовать как readiness gate; unchanged no-op не доказывает four-store rotation. Старый8080 scheduler не направлять на8081.

## Актуальная source-валидация

- Final API: **1322 PASS**, API TypeScript PASS; targeted sanitizer/history HTTP **19 PASS**. Disposable/fake-provider seams, не real generation.
- UI: **616 PASS / 29 files**, frontend typecheck PASS; main/admin builds PASS. Main Vite chunk >500kB warning сохраняется.
- После type-only исправления qualification helpers root lint **PASS**; offline qualification runner **7 PASS**. Type-erased AST совпадает, но historical evidence source hashes изменились: native Secrets qualification не повторялась, packets не переписывались.
- Public LLM/CVE/refresh/scheduler final maintenance suites: **239 PASS**, Python config/provision **14 PASS**. Это включает реальные временные SQLite snapshots и injected Docker fixtures, **не live deployment PASS**.
- Native browser runner offline **29 PASS**; live Chromium/proxy fence/scanner/provider не выполнялись.
- Known SSE/UI intermittency не объявлена fixed.

## Flownix

Fresh policy: full/strict, approval=false, spec_first=false, parallel/direct.

Полные resulting bodies validated/proposed/applied, 0 removed/renamed requirements:

| Doc | Version | Source | Applied revision |
| --- | --- | --- | --- |
| DIP-DOC-1 | 5→6 | DIP-TASK-2 | `8096b344-f848-4d8b-b1be-7953cee30c49` |
| DIP-DOC-2 | 7→8 | DIP-TASK-9 | `b5a758c5-af6d-4fdf-b78b-2c268653ed31` |
| DIP-DOC-6 | 2→3 | DIP-TASK-2 | `e613a565-dfe1-4ce6-8bc1-daa710fef535` |

Полные fresh bases сравнены вручную; machine-exact remote hash не заявляется. Component bindings сохранены. Старые stale proposals не удалялись. Новых task done **нет**; TASK2/3/4/9 acceptance не закрыта, принятые14/16/21/39/40/41 автоматически не переоткрывались. Applied spec не равен runtime acceptance.

## Git

Текущая ветка остаётся `feat/dip-task-30-21st-components`, без новой ветки/force/main merge. Commit/push фактически сообщаются отдельно после выполнения; private DB/backups/keys/.local state исключены. Этот документ не заявляет commit или push до получения Git результата.
