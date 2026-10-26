# Public automation: итог на 26 октября 2026

## Коротко

Сканирование, приблизительный прогресс, компактное покрытие и чтение отчёта проверены в новой реальной браузерной попытке. Интерфейс чата доступен сразу, настройки original сохранены с явным согласием. **Успешная работа ИИ ещё не подтверждена:** единственный автоматический запрос сводки завершился локальным deadline/timeout. До вопросов чата и перевода проверка не дошла. Новых попыток этот документ не разрешает.

По актуальной передаче координатора стенд READY, 425 source hashes совпадают, данные runtime сохранены. Это отдельное подтверждение развёртывания, не доказательство качества или успешного ответа модели. Автор этого документа читал готовые артефакты и Flownix; runtime, провайдер и тесты здесь не запускались.

## Последняя реальная попытка

- Attempt: `60aa9db1-4784-4866-a8ec-9131a5cb2035`.
- Run: `1fa31ead-7a60-47f8-986d-2e26e25606df`.
- Время: **2026-10-26T20:44:16.870Z–20:45:53.047Z**.
- Scan: `22e240ac-5ed2-402a-be8d-a5212722fed3`, completed. Координатор подтверждает все четыре выбранные проверки checked; JSON фиксирует completed и набор secret/sbom/vuln/config.
- Совпадающие исходные артефакты: [JSON](public-automation-60aa9db1-4784-4866-a8ec-9131a5cb2035.json) и [Markdown](public-automation-60aa9db1-4784-4866-a8ec-9131a5cb2035.md). Оба прочитаны полностью, не изменены.

В этой попытке **12 PASS / 14 BLOCKED / 0 FAIL**, но полный AI-сценарий не принят.

**Подтверждено в её области:** создание владельца и native scan; приблизительный прогресс; переход к покрытию без дополнительной генерации; отчёт с **161 строкой vulnerabilities на четырёх страницах**; сразу доступный чат; сохранение original preferences с явным согласием; первоначальный passive GET summary с ожидаемым `404 LLM_SUMMARY_MISSING`; anonymous denial `401`; сохранение исходных текстов и counts; safety с **0 guard violations и 0 page errors**. Число строк не означает число уникальных CVE. Доступность чата не означает успешный ответ на вопрос, а cache-miss не означает успешное восстановление сводки.

### Что произошло со сводкой

Допущен **один summary POST**. Артефакт сохранил HTTP503, `LLM_REQUEST_ABORTED` и diagnostic headers **phase=deadline / reason=timeout**. Это отказ по deadline на стороне приложения, **не установленный upstream HTTP503**: `providerFailure.status` отсутствует. Из этого нельзя вывести provider busy, исчерпанную квоту, проблему модели или точную внешнюю причину.

Consumption указан как **UNKNOWN**; независимое наблюдение server egress и проверка billing отсутствуют. Даже записанное в preservation `costMicros=0` не доказывает нулевого расхода этой допущенной попытки. Успешный summary result не получен и не реконструируется; неизвестное потребление не обнуляется и не возвращается автоматически.

После отказа сработала остановка: **chatPosts=0, translationPosts=0**, всего passive summary reads=2. Chat, translation, успешная история и восстановление summary после reload/fresh login остались BLOCKED по stop/prerequisite. Вторая owner-сессия для проверки изоляции настроек не была разрешена; anonymous401 не заменяет foreign-owner proof. Нового native attempt после этой попытки не выполнялось по текущей передаче координатора.

## Развёртывание, спецификации и тесты

По передаче координатора: один normal rollout READY, audit `deploy-ed3d33be2f2b7fcc19e33544cea7b195`, four stores/JWT сохранены, lock отсутствует; 425 source hashes совпали, 8081/8080 HTTP200 и scheduler status PASS. Независимые final AI/cache и progress/coverage reviews дали GO после P1/P2 fixes. Эти operational результаты не перепроверялись данным документным шагом.

В Flownix уже применены точные reviewed тела: **DOC2 v10, DOC8 v6, DOC9 v4, DOC15 v5, DOC16 v5**. Все пять сохранённых документов прошли `validate_spec: valid:true`; IDs, bases и timestamps находятся в [apply manifest](public-automation-20261026-apply-manifest.md) и [receipts](public-automation-20261026-apply-receipts.json). Это implemented-контракты, не native AI/semantic/privacy/billing acceptance. Старые подготовительные HOLD/NOT APPLIED пометки в неизменённых телах не отменяют последующие реальные apply receipts.

Актуальные результаты тестов **сообщены координатором**, здесь не перезапускались:
- full API — **1411 PASS**;
- текущие root TypeScript, lint, main/admin builds — **PASS**;
- full UI — **994 PASS до последних узких изменений**; отдельно targeted **160 progress / 366 summary / 143 translation PASS**;
- runner — **130 offline PASS**.

Это разные прогоны, не новый совокупный full-UI результат. Два прежних paging-теста в том прогоне прошли; это не доказательство исправленной причины их прежней нестабильности. Offline runner PASS не заменяет native qualification.

## Что остаётся неподтверждённым и какие ограничения действуют

1. **Реальное успешное завершение ИИ.** Не подтверждены новая русская сводка, два успешных ответа чата, история успешных ответов после reload/fresh login и машинный ru-перевод с проверкой смысла. Последний наблюдаемый blocker — application deadline/timeout summary и последующая остановка сценария. Старый translation predicate или точный provider root cause из него не восстанавливаются.
2. **Сводка хранится только в процессе API.** Public cache ограничен 64 entries / 2 MiB accounted / 64 KiB result. Browser reload и fresh login могут восстановить результат через passive GET лишь пока тот же instance удерживает подходящий owner/report/policy entry и текущий доступ разрешён. API restart, eviction или другая replica теряют cache; DB durability и гарантированный срок не обещаны. В этой попытке успешное восстановление не проверено.
3. **Настройки локальны браузеру и владельцу.** Они не синхронизируются между устройствами и не заменяют серверный consent. Свежие snapshot identity/session/применимые flags и exact disclosure проверяются перед передачей и публикацией. Attempt markers и локальная очередь не дают глобального exactly-once; miss не разрешает replay, abort не доказывает прекращения внешнего вызова. Перевод остаётся memory-only и после reload не восстанавливается.
4. **Прогресс остаётся оценкой.** Неравные веса — локальная модель, не измеренная длительность. Серверный percent остаётся null; 100% только после подтверждённого completed. Наблюдаемая регрессия outcomes сбрасывает оценку, невидимый внутренний retry надёжно не определяется.

Fixed пара остаётся **OpenRouter / xingchen-agi/xing4.0-29b-a4b:free / Phala**. Public-only GET recovery не является запретом на app-wide authorized automatic POST для legacy report, но exact provider/disclosure guards сохраняются; разрешения на другую модель, paid fallback или повтор здесь нет. Вопросы чата по-прежнему отправляются только вручную.

## История и состояние задач

Предыдущая попытка `1f09fff7-5134-4461-873b-0519452c359b` сохраняет свой **report assertion FAIL** и неизвестный исход одного summary POST после раннего закрытия браузера. Новая попытка с успешным report — отдельное evidence, не исправление старого FAIL задним числом. Её runner assertion fix также не доказывает root cause прежних paging failures. Старые AI FAIL/BLOCKED и unknown liabilities остаются в исходных файлах.

В новом Markdown-артефакте сохранилась шаблонная строка о source412. Она не принимается за актуальное состояние стенда: текущие 425 совпавших hashes/READY приведены выше именно как более новая передача координатора. Исходный артефакт не переписан.

Свежие TASK9/TASK42 и их комментарии прочитаны: **TASK9 — regression, 85%; TASK42 — blocked**. Устаревшие button-only/no-auto/policy формулировки в прежних записях являются историей; текущие контракты задают применённые версии документов выше. Эта запись обновляет evidence, а не меняет критерии или статусы. Задачи и родители не закрывались и не переоткрывались; новых дельт, source/runtime/provider/Git действий нет.
