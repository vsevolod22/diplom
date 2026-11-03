# Диплом — анализ безопасности OCI-образов

Веб-приложение для запуска разрешённых проверок образов, просмотра CVE, SBOM и Secrets, событий задания и доказательной ИИ-сводки/чата. React 19 + TypeScript + Vite, NestJS, SQLite ledger/outbox и изолированный worker с Trivy. Демонстрационные данные явно отделены от реального сканирования.

## Текущий статус — website batch READY, native NONAI scoped verification

По handoff координатора: **`d638284da9710feaa0f6f73a5c8e98dd` READY**, source `d41ce475b2a0b8206b9dd32ddd4ebd582350c9e1ba22d8a383b5b52ef7644ca4`, **517/24**, API healthy / root200 / anonymous auth401; четыре хранилища сохранены. **Native NONAI: scoped checkpoints PASS**, одна закрытая browser session/account, два scan (normal + own cancel), cancel POST1 / LLM POST0. Проверены list/create/keyboard/mobile375 overflow0, throwing storage getItem, active<100/reload→completed100/all4checked, SBOM focus/draft, cancel200→GET/reload cancelled без auto POST, logout→cached email hidden/me401/report denied. Lost-response cancel и SSE-close при logout **live NOT_VERIFIED** (focused tests отдельно). Две начальные ошибки runner assertions сохранены; historical unhandled cause UNKNOWN, не доказанный app bug. Offline runner8 PASS — не повтор journey. Это не whole-website/full-clean PASS; [evidence и границы](docs/openai-integration-20261101.md#native-nonai-на-batchd638--фактически-проверенный-scope).

В batch включены session/SSE fencing, replay/503 fixes, storage fallback, устойчивые controls/focus, cancel recovery и reactive auth gate. Frontend **2d GO**, reactiveP2 closed, Sol **13UX+10gate+1TSfix PASS**, root typePASS; backend **e2 GO, Sol16/APItsc PASS**. Capacity **18 PASS/168c GO**, catalog **33/48 (active24/archive9)**, refs **49/128**; archive/deletion не выполнялись, прежний capacity blocker снят.

**`gpt-5.4-mini-2026-03-17` активен в uncapped**, с техническими ограничениями и accounting; OpenRouter сохранён без fallback, secret server-only. Две отдельные native AI-проверки ниже относятся к предыдущему deployment **`537a8e5a18ba50d4ff9a09e6c486ce73`**, не к повторной проверке нового batch.

Structural ответ — качественная русская проза: начало русской буквой, минимум три русские буквы, без латиницы/цифр/скобок; точные технические факты сервер выводит в source cards каждого абзаца. Policy связывает prompts+schemas; posttranslation/repair/retry нет.

- **Native summary PASS:** собственный completed scan, 1 POST → HTTP200, exact source cards, durable GET/reload без нового POST; input13489/output738, estimate **$0.013438**, held0 в этой проверке.
- **Отдельный CHAT-ONLY PASS:** summary0/chat1 POST → HTTP200, настоящий NDJSON completed, history1turn, reload без POST и source cards; estimate **$0.014098**, held0 в этой проверке.

Это не combined run, не invoice, не глобальное отсутствие liabilities и не приёмка legacy/всего сайта. Прежние guard/HTTP failures и **57497 microUSD unknown held** сохранены, не очищены. **Больше платных вызовов не выполнять.** Auth proxy-IP shared20 — отдельный public multiuser hardening вне local batch; report export не обещан. TASK2/4 security и host-broker scope этим выпуском не закрываются.

[Краткий handoff, source identity и история](docs/openai-integration-20261101.md). **DOC17 v2 applied** (`9c7fa16b-d107-4f5f-a868-2c2df04cc5a8`); узкий контракт missing-ledger503/genuine-missing404 — **DOC7 v4 applied** (`c9a57823-6a85-45a9-adda-4df6e163aff1`,1 added, прежние требования сохранены). Остальные исправления уже покрыты спецификациями. Эта docs-only правка не запускала tests/runtime/paid calls; статусы задач не менялись.

## Предыдущая source-сверка — 01.11.2026: OpenAI offline, НЕ deployed (история)

Ниже сохранён снимок до activation/rollout/native; его блокеры не являются текущим статусом.

Direct OpenAI summary/chat, explicit uncapped accounting, backend runtime, paid-consent UI и v6 deployment source в основном реализованы. Выбор владельца: `gpt-5.4-mini-2026-03-17`, **без локального денежного лимита** (`uncapped`/`null`), но с конечными техническими ограничениями и учётом usage/unknown; это не бесплатность. Rates не имеют defaults и не активированы.

**Real key не установлен, live OpenAI и v6 rollout не выполнены.** Runtime читает `OPENAI_API_KEY` только из ENV API-процесса; отдельный защищённый bootstrap готовит её из readonly volume без Docker `Config.Env`. OpenRouter default сохранён, fallback нет; summary/chat сразу русские, отдельный OpenRouter translation недоступен при uncapped. Старое free-согласие не разрешает paid.

Сообщённый основной сессией 8081 `136… READY` здесь не перепроверялся. Ранние NONAI native 8/8 с нулём LLM calls и API1731/UI1331 не являются итоговым PASS последних fixes. Independent v6 review и coordinator final-review GO ещё нужны; дельта DOC17 подготавливается **без применения**, задачи не закрываются. [Source-контракты, evidence и оставшиеся gates](docs/openai-integration-20261101.md).

## Предыдущий статус — 01.11.2026, после deploy6a731 (история)

Ниже сохранён прежний итог основной сессии, не новая runtime-проверка. Исторические FAIL/PASS сохраняют свой scope и не становятся приёмкой OpenAI или новой версии.

- **8081 READY:** `deploy-6a731865544bd09fe4e358be2d1464ab`. Проверены 446 source-файлов, в том числе 326 API и 6 runtime; hash реально отдаваемого web bundle и новая подпись настройки подтверждены. Четыре хранилища сохранены: 12 snapshots, `B0 == fenced == before == after`, history schema4, key/JWT сохранены. Удерживаются 16 image references; защищённый8080 не трогали.
- **Production:** конечная privacy-safe диагностика grounding (predicate/index и witness из трёх enum-полей), без ослабления guards. Три реальные red-регрессии языка исправлены для уже разрешённых TLS/SBOM и процитированного `libc6`: кавычки, неразрывный дефис, ASCII-многоточие; словарь не расширен. **3 RED → green**, полный API **1594 PASS**, typecheck/lint PASS, независимый review GO остаются валидными source-проверками, но не устанавливают причину исходного native отказа.
- **ИИ-отчёт и чат сразу на русском, без последующего перевода:** service/UI tests подтверждают success и language-failure пути с одним provider reserve/dispatch, без нового repair/retry. Независимый перевод исходных advisory сохранён. В [настройках](src/features/auth/ReportPreferencesPanel.tsx) изменены только формулировки/доступное описание: «Язык исходных описаний уязвимостей»; stored preference, consent revision, payload и auto-summary behavior прежние. Новая конечная [language-диагностика](server/api/src/llm/language-rejection.ts) reason/index/tokenClass сохраняет privacy, без ослабления acceptance.
- **Последние проверки:** полный API **1608 PASS**, UI **1264 PASS**, mock E2E **48 PASS**, main runner **61 PASS**, lint/typecheck PASS. Исключение: дополнительный SSE scope **42/44 PASS, 2 FAIL** на source-assertions (`defaultValues` literal и отсутствующий slice-end marker); здесь не исправлялись, baseline не доказан. Это не общий all-green.
- **Последний native summary, выполненный после typography deploy439b — FAIL:** [attempt `cd984cf2…`](docs/public-automation-cd984cf2-2869-4527-97a8-fc923fdf8c2a.json), scan `64b982ae…`: ровно1POST → HTTP502 `language/not_russian`. Точный отклонённый фрагмент **UNKNOWN**; после отказа дальнейшей генерации в попытке не было. Успешный summary на последней версии не доказан, **durable reload заблокирован**.
- **Native перевод не принят:** после исправления runner `79a0` (**60 offline PASS, review GO**) [attempt `8d53d663…`](docs/public-automation-8d53d663-67d1-4e00-bfb7-137e58baa6b3.json), scan `cba16e03…`: один translationPOST → HTTP502 `translation_title/not_russian`, summary/chatPOST0. Настоящий scan/all4checks, progress,161findings/4pages, coverage/auth/preservation — PASS; translation toggle заблокирован. В обеих попытках браузер закрыт, active scans0, safety violations0. **В новом инкременте native/provider запросов не было**; deploy6a731 не получил новой native ИИ-приёмки. Успех LLM и причина прежнего отказа по-прежнему не доказаны.
- **CVE refresh заблокирован:** единственная native загрузка завершилась `fetch/CHILD_TIMEOUT` через240с; partial **132213568 bytes** сохранён в `.cve-refresh-work`. Fence/lifecycle не начинались, сайт не изменён. Active DB от28.10 остаётся usable до11.11, scheduler disabled. Следующий refresh блокируют retained staging и capacity (теперь active17); partial не изменён, cleanup/retry не выполнялись.
- **Evidence сохранены:** ранее архивированы целиком 8+1 набора, без удаления; после нового deploy **active17 / archived9 / total26**, сохранены 3 CVE backups. Current-only capacity/transfer fixes и их scoped проверки не означают успешный native refresh или новый full-all PASS.

[Подробный текущий итог, границы проверок и оставшиеся блокеры](docs/public-finish-20261028.md).

## Предыдущий статус — 31.10.2026 (история)

### Последнее развёртывание: основной путь и durable summary

**Сайт работает: http://127.0.0.1:8081, API healthy. Полная ИИ-приёмка НЕ пройдена.** Последний normal rollout `deploy-44236d35f3b78d1b16466adb3371bc2f` завершён READY: проверены 441 build-source файл и полное равенство четырёх хранилищ до/после запуска API. Аккаунты, исходные отчёты, история чата, JWT, ключ и квоты сохранены. Защищённый8080 в этой сессии не обслуживался.

Поставлены исправления прогресса/отчёта ниже, а также:
- Форма запуска блокируется во время отправки. Неопределённая попытка переживает временный сбой сессии в памяти вкладки; после повторной проверки того же владельца ручной повтор использует прежний idempotency key, но требует нового согласия и допуска. Закрытие вкладки/полный reload не сохраняет этот intent.
- Временная ошибка `/auth/me` скрывает приватный экран, но не делает logout; доступны ручные повторы проверки сессии, допуска после403 и первой загрузки списка. Вход возвращает на разрешённый внутренний адрес отчёта/запуска.
- Проверенный ИИ-разбор сохраняется в существующей history SQLite **до успешного HTTP-ответа**. Read-only GET повторяет auth/report/policy/source checks; storage fault не выдаётся за отсутствие результата. Хранилище ограничено, без удаления прежних результатов ради новой записи. Chat/translation egress не расширен; перевод по-прежнему не имеет persistent cache.
- Явная миграция history v3→v4 выполнена с проверкой точного schema relation, сохранением всех прежних строк/incarnation и последующим полным four-store comparison. Первый rollout остановился до миграции на недоступности старых image metadata; exact-audit continuation завершился READY, original evidence сохранено. Recovery token не повторять.
- Повторные normal builds теперь сохраняют четыре прежних image ID через проверяемые audit-bound retention tags. Последний build прошёл без потери этих references; теги/образы не удалялись.

**Проверки Sol6.1:** full UI **1259/1259**, full API **1501/1501**, mock Chromium **46/46** + long-reference **6/6**; root/API typecheck, lint, main/admin builds PASS. После узких typography-исправлений отдельно прошли49 API checks; retention/current/historical/recovery/migration/CVE qualification —386 checks PASS в своих scoped suites, не новый полный application rerun. Отдельные coverage mock cases2/2 и runner49/49 PASS. Предыдущие concurrency flakes и warning chunks>500kB не объявлены исправленными. Production/review — Astra, тесты — Sol6.1.

**Последняя настоящая проверка:** [attempt25544b30…](docs/public-automation-25544b30-2211-41b2-bfc8-190864c3d4b0.json), scan`902b37fa-90ac-4d8c-894d-056a2f9c098e`: completed/all4checks, прогресс/coverage warning/auth/findings161/4pages/preservation/safety PASS. Единственный summaryPOST получил application502 `LLM_INVALID_RESPONSE`, **grounding/unknown_identifier**; конкретный identifier и причина неизвестны, raw ответ не сохранялся. Chat/translationPOST0 после остановки. Retention header `durable-owner-scan` подтверждён, но native восстановление успешного нового summary не проверено. Ранее в этой сессии summary`7f1…` завершился language/not_russian, isolated chat`d2ce…` — upstream400; исторические FAIL не переписаны. Две отдельные tiny synthetic chat проверки получили HTTP200: одна rejected language, другая schema/citations/Russian PASS; это не приёмка реального чата/семантической точности. Новых повторов/fallback/refund нет.

**Остаётся:** устойчивый успешный native ИИ-отчёт, два chat turns/history и перевод; semantic quality; квалифицированное CVE refresh. Scheduler выключен. Проверенный active CVE UpdatedAt `2026-10-28T01:21:08.391884645Z`, usable-until `2026-11-11T01:21:08.391884645Z`; устаревание честно предупреждается, timestamps/TTL не менялись. TASK46/47 testing, BUG2/TASK42 blocked, родители не закрыты. Коммитов/новых веток нет.

### Предыдущий инкремент рабочей копии — теперь включён в развёртывание

В рамках `DIP-BUG-2` / `DIP-TASK-43–45` исправлены воспроизведённые ложные `LLM_INVALID_RESPONSE`: подтверждённые оценки CVSS (в том числе `10.0`, десятичная запятая и скобочная форма), отдельно точные версии стандарта CVSS и package/version после русских labels без пробела. Неподтверждённые значения и некорректные числовые формы отвергаются; версии пакетов не служат доказательством оценки. Защита источников, языка, прав доступа и внешней передачи сохранена. Причина конкретного пользовательского запроса без его диагностики не установлена.

Прогресс скана теперь различает серверный процент, явно приблизительную оценку и отсутствие измеримых данных. Список без detail-метаданных не показывает конкурирующий процент; 100% означает только подтверждённый completed. Временная потеря набора проверок приостанавливает локальное наблюдение без обнуления/учёта паузы; панель и исходы проверок используют один снимок данных. Есть ручной повтор получения статуса.

ИИ-отчёт показывает реальные этапы: доступность → поиск сохранённого разбора → ожидание/генерация → проверка источников → готовность. Индикатор без выдуманного процента/ETA, с временем ожидания; ошибки объяснены по-русски, повтор остаётся ручным. Технические сведения scanner/DB свёрнуты, предупреждения об устаревших данных и исходные находки доступны. Навигация отчёта адаптирована для мобильного и широкого экрана.

**Проверка рабочей копии:** UI `pnpm test --maxWorkers=1 --reporter=dot` — **1238/1238**, полный API с `--test-concurrency=1` — **1488/1488**, mock Chromium `pnpm exec playwright test --config tests-e2e/playwright.config.ts --workers=1` — **46/46**; typecheck/lint/main+admin builds — PASS. Параллельные полные прогоны ранее давали timeout/connection flakes; их первопричина не объявлена исправленной. Основная сборка предупреждает о chunks >500kB. Тесты выполнял GPT-6.1-Sol, код и review — GPT-6-Astra. Реальный LLM, native scanner и развёртывание этих изменений не запускались; данные/модель/квоты стендов не изменены. Ниже описано ранее развёрнутое состояние, не доказательство выкладки этого дополнения.

### Историческое состояние до последнего развёртывания (не текущая приёмка)

**Сайт запущен: http://127.0.0.1:8081.** Финальная новая сборка развёрнута с сохранением accounts/reports/JWT/history/quota; API healthy. Защищённый8080 также отвечает HTTP200 и не обслуживался. Новый ночной CVE-инцидент `refresh-172233a7b4b082b6b721a0e476bcd2d4` восстановлен и архивирован после сравнения четырёх хранилищ. **Проблемное автоматическое CVE-обновление отключено и выгружено из launchd**, чтобы не останавливать сайт снова. Не включать его до исправления и отдельной проверки refresh; существующая DB не становится свежее и после14суток перестанет допускать новые CVE-сканы.

По уточнению владельца экран теперь содержит **ИИ-отчёт → исходные находки → ручной чат**. Разбор запрашивается автоматически после completed scan с применимым opt-in; служебные стены модели/политики/квот не показаны. В `/account` доступны язык original/ru и «ИИ-разбор», с явным сохранением. На странице отчёта можно один раз нажать «Включить авторазбор» с кратким раскрытием внешней передачи и возможного хранения. Новая revision `report-automation-v4-remediation` не переносит прежнее согласие. Разбор запрашивает приоритеты, действия и обоснование по sanitized packageName/installedVersion/reported fixedVersion (null означает неизвестно); advisory free text, credentials и raw output не передаются. Исходный отчёт остаётся доступен при сбое ИИ; auth/owner/report/policy/source/quotas сохранены.

**Настоящий автоматический ИИ-отчёт проверен31.10:** attempt `a6b6d59c-b518-4df6-93cd-e183277c12b8` прошёл все11 обязательных summary-проверок. После настоящего completed scan — один автоматический POST, HTTP200 и отображение русского текста; после reload — тот же результат через GET без повторной генерации.161CVE/4страницы и исходные данные не изменились; guard/pageErrors0. Scoped API и браузерные tests, root/API typecheck, lint/diff — PASS; независимое review языковых и source-bound границ — GO. Это не новый полный suite и не приёмка чата/перевода.

**ИИ-отчёт работает:** exact бесплатная модель `dots-studio/dots-3-note-preview:free`, единственный endpoint `atlas-cloud/fp8`, no-training/non-ZDR с возможным хранением, `data_collection:deny`, нулевые caps/budget, без fallback/автоповтора. NVIDIA исключена из-за несовместимой training-policy. Guarded migration Dots2048→descriptor v5 `public-8081-remediation-4k-v1` и normal `up --build` выполнены: READY с сохранением accounts/reports/JWT/history/quota. Output теперь4096 только в exact public policy, legacy2048 не расширен;90/95/100/105/120s и byte limits прежние. Prompt hash `russian-remediation-v10-bounded`:4–6 коротких абзацев до1600символов, provider schema ограничивает массив6абзацами, каждый до320символов и1–2citations. Разбор сохраняет все critical/unknown findings плюс до8 необязательных приоритетных; общие counts/пропуски указаны честно. Конечный словарь обычных технических сокращений больше не вызывает ложный отказ русского текста; произвольная английская проза, выдуманные CVE/версии и непроцитированные пакеты по-прежнему запрещены.

Финальная native квитанция: [a6b6d59c…](docs/public-automation-a6b6d59c-b518-4df6-93cd-e183277c12b8.json), scan `607557c0-8651-4f58-9a5b-29501937553a`. Из162findings модель получила23 (все обязательные+8optional),139явно пропущены; полный scanner report доступен отдельно. Реальная генерация/отображение/reload/preservation — PASS. Проверка формы/русской прозы/citations не доказывает абсолютную semantic fidelity; chat/translation в этом summary-only запуске не вызывались. Кэш сводки process-lifetime, не переживает API restart/eviction. Старые881ae8fc languageFAIL,67b7 HTTP200 observerFAIL и23e5/572d finish_length остаются историей, неизвестный расход не сброшен. `DIP-TASK-42` не закрыта целиком из-за оставшихся chat/translation AC; current summary contract применён в DOC8v9/DOC9v7. [Единый итог и оставшиеся работы](docs/public-finish-20261028.md).

Очистка29.10: удалены лишние CVE payloads **5.269GB** и старые worktree `diplom-task-{2,3,12}` около**2.09GB**, ветки/коммиты сохранены. После последних сборок отдельно удалены47 private build-cache записей диплома — **4.181GB по Docker prune**; это не повторное удаление CVE и не сумма гарантированного host reclaim. Рабочие базы, accounts/reports/JWT/history/quota, архивы и protected8080 сохранены. Новые CVE-копии не создавались.

## История — 27.10.2026: первое восстановление и отказ ИИ

**Сайт работает: http://127.0.0.1:8081 — HTTP200; защищённый8080 — HTTP200.** Восстановление CVE-инцидента `refresh-ae36659bf3268f7e6cb93d8d070ac77d` завершено `recovered-archived`: контрольные копии четырёх хранилищ до и после запуска API совпали с исходным baseline, прежний web запущен последним, исходные журналы и lock сохранены в целом архиве. Затем выполнена обычная новая сборка/развёртывание с сохранением accounts/reports/JWT/history/quota. API healthy; активных operation/recovery locks нет. Старые recovery tokens использованы и не подлежат повторению.

Увеличение ожидания **применено и развёрнуто**: actual descriptor v2 `public-8081-90s-v1`, API90s / gateway95s / proxy100s inter-read / client105s / whole UI120s. Модель, бесплатный режим, privacy, token/byte/budget caps не менялись. Применены три ранее подготовленные timing-дельты: DOC8v7, DOC15v6, DOC16v6; это контракт развёрнутого поведения, не подтверждение успешной генерации.

Новый native browser scan завершился `completed`: все четыре проверки checked, отчёт161CVE/4страницы, приблизительный прогресс и автоматический summary POST без кнопки проверены. **Единственная сводка получила upstream429 `LLM_PROVIDER_RATE_LIMITED`** — это внешний отказ, не прежний timeout и не успешный ответ ИИ; точная причина ограничения неизвестна. Chat/translation POST0, повторов/fallback/refund нет, consumption UNKNOWN. Успешные чат, сводка и перевод остаются непроверенными. [Итог восстановления, проверки и оставшийся блокер](docs/public-restored-20261027.md); [санитизированная native-квитанция](docs/public-automation-2b952480-d04f-49e4-bf26-c57ff77c57b3.json). Предыдущие HOLD-документы ниже — история, не текущее состояние; `public-cve-completion.mjs` по-прежнему только offline checker. Не повторять старые recovery/timeout migration и не удалять архивы или quota liabilities.

## Историческое рабочее состояние — 26.10.2026, до нового CVE HOLD

**Scanner работает: http://127.0.0.1:8081. Защищённый8080 также отвечает HTTP200.** Новые сборки развёрнуты с сохранением accounts/reports/JWT/history/quota; operation lock отсутствует. Проверены7services/6networks, API healthy, API-only readonly key volume и worker4GiB/CPU1/PIDs128. Старые recovery tokens уже consumed — не повторять. [Актуальный итог автоматизации и настоящей проверки](docs/public-automation-20261026-final.md). Последний rollout `deploy-ed3d33be2f2b7fcc19e33544cea7b195` завершён READY;425файлов build-source сверены побайтно. [Предыдущая финализация](docs/public-finalization-20261026.md) сохранена как история.

### Сканирование и прогресс

Откройте `/register` или `/login`, затем `/scans/new`: введите public Docker Hub reference, выберите `linux/amd64`, проверки и подтвердите цель. **Вся строка скана кликабельна**, включая название. На странице и в списке показывается **приблизительный процент**, а не25%закаждуюпроверку: загрузка и анализ уязвимостей весят больше конфигурации, оценка постепенно меняется по времени наблюдения и подтверждённым итогам. Это некалиброванная эвристика, не измеренный процент работы и не ETA; невидимые внутренние повторы могут её завышать.100%показывается только для подтверждённого `completed`, не для failed/cancelled. Серверный `percent:null` не подменён. Исходы проверок показаны компактными плитками; технические версии раскрываются отдельно.

Реальный browser scan26.10 завершился `completed`, все4checks `checked`: **161CVE,0DebianTEMP,4страницы** на конкретных pinned image/DB. Свежий вход, ownership404/UI denial и сохранность отчёта прошли. Отдельный native progress/cancel workflow — **10/10PASS**: после отмены сохранён завершённый config-check; остальные проверки остались unknown, не0. Старые FAIL сохранены отдельно, не переписаны.

### Настройки языка и автоматическая ИИ-сводка

В `/account` выберите **«Язык отчёта: оригинал / русский»** и режим краткой ИИ-сводки, затем сохраните настройки. Они привязаны к аккаунту **в этом браузере**. До явного сохранения автоматика выключена; рядом раскрыты точная бесплатная пара, передаваемые поля и ограничения. После включения сводка запрашивается автоматически при завершении скана, без «Получить сводку». Чат и поле вопроса открываются сразу; сам вопрос отправляется пользователем. При выбранном русском языке открытая карточка advisory автоматически переводит свои разрешённые поля; весь отчёт заранее провайдеру не рассылается. Закрытие, отзыв выбора или смена аккаунта отменяют ожидание; очереди ограничены, автоматических повторов отказов нет. Ключ уже подключён API-only readonly — вводить его повторно не нужно.

Новые summary/chat запрашивают русский текст и проходят консервативные language/grounding guards; теперь запрашивается точная JSON Schema для каждой операции. Находки scanner отделены от интерпретации ИИ. Оригинальные advisory не переписываются. Готовая public-сводка читается без генерации после reload/повторного входа, пока сохраняется ограниченный кэш процесса API; **не переживает перезапуск API или вытеснение**. История чата сохраняет отдельный durable-контракт. NDJSON доставляет завершённый проверенный ответ, **не native token streaming**.

**Успешная реальная генерация всё ещё не принята.** Последний native attempt `60aa9db1…`: scan/оценочныйпрогресс/покрытие/отчёт/сразуоткрытыйчат/settings-original/passive-summary-404/anonymous401/preservation/safetyPASS. Один автоматический summary POST получил **application503 `LLM_REQUEST_ABORTED`, `deadline/timeout`**; это не доказанный upstream503. ConsumptionUNKNOWN, chat/translationPOST0 — дальнейшая генерация остановлена. Более ранние provider429 и translation invalid_content остаются историческими фактами; новая попытка не установила их причину. Фиксированная бесплатная пара OpenRouter `xingchen-agi/xing4.0-29b-a4b:free` → `phala` не менялась; paid/автоматического fallback и refund/reset нет. Смена профиля или лимитов требует отдельного решения, а не скрытого повтора.

### CVE, проверки и процесс

Новая public CVE release активирована с four-store preservation; UpdatedAt **2026-10-25T19:10:35.479132794Z**. Отдельный public scheduler установлен и проходит status-проверку: **каждые6часов**, без RunAtLoad/KeepAlive. Успешный periodic-run receipt отдельно не заявляется. Локальная подпись оператора — **не Aqua publisher signature**; LOCAL8080 updater не используется для8081.

Свежий полный API: **1411/1411PASS**. Полный UI: **994/994PASS** до последних узких правок; после них отдельно прошли143translation/160progress/366summary-targeted и130offline-runner тестов. Старые два paging timeout в новом полном прогоне прошли, но их первопричина не объявлена исправленной. Typecheck/lint/main+admin buildsPASS; Vite chunk warning сохраняется. Новая работа выполнена пятью параллельными авторами с отдельными reviewer/spec/browser/security lanes. Applied DOC2v10/DOC8v6/DOC9v4/DOC15v5/DOC16v5; TASK9/TASK42 не закрыты поверх непроверенных критериев.

### Исторический LOCAL профиль (8080 защищён, не управлять для запуска public8081)

Полный локальный стенд запускается через `pnpm stand:local` на **http://127.0.0.1:8080**: собранный frontend/nginx, Nest API, постоянные SQLite-базы, worker и gateway. Проверен настоящий UI-запуск Secrets/SBOM/CVE/Image config с отчётом, reload и повторным входом. Это отдельный project `dip-local-full` с новыми данными, не восстановление старого окружения. **Развёртывание на сохранённых пользовательских данных не завершено.** Старый Docker-стенд находится под HOLD после прерванной сохранительной миграции; не запускайте на нём `stand:auth`, refresh/recreate helpers, удаление контейнеров или volumes без отдельной проверки восстановления. См. [итоговую матрицу](docs/release-readiness-20261015.md) и [операционный HOLD](docs/deployment/hold-handoff-20261015.md).

Зелёные unit/browser tests не означают готовность публичного сервиса. Для публикации нужны TLS, ограничение злоупотреблений, проверенные backup/restore и отдельная runtime-приёмка. ИИ и runtime/host capabilities включаются отдельно; наличие кода или аккаунта не предоставляет разрешение на сканирование.

## Исторический LOCAL запуск (не выполнять на этой машине для public8081)

Ниже сохранена инструкция отдельного LOCAL-профиля8080. Сейчас он защищён; для работающего public8081 launcher не нужен. Не запускайте LOCAL команды обслуживания без отдельного разрешения.

Для новой независимой LOCAL установки требовался запущенный Docker Desktop. Из корня `diplom`:

```sh
pnpm stand:local         # собрать и запустить в фоне; первый запуск может занять несколько минут
pnpm stand:local:status  # состояние только нового dip-local-full
pnpm stand:local:stop    # остановить без удаления аккаунтов и отчётов
```

Откройте http://127.0.0.1:8080/register и создайте **новый локальный аккаунт** с паролем от 12 символов. Затем откройте http://127.0.0.1:8080/scans/new, выберите **Alpine 3.20**, отметьте **Secrets, SBOM, CVE, Image config**, подтвердите цель и запустите скан. Результат появится на странице задания и останется в `/scans` после повторного входа. Здесь нужны страницы `/scans`, не `/demo/scans`; порт `5173` — другой dev-режим.

**Исторически для LOCAL8080 CVE был подключён и настроено обновление каждые 6 часов (не public8081)** через отдельный macOS LaunchAgent. Текущая подписанная локальным оператором база имеет UpdatedAt `2026-10-16T01:13:54.947090392Z`; настоящий browser scan с новой базой проверен. `pnpm cve:auto:status` показывает расписание и последний результат, `pnpm cve:refresh` запускает проверку вручную. [Автообновление и ограничения](docs/local-cve-auto-refresh.md), [первоначальное подключение и доверие](docs/local-cve-20261016.md). Alpine 3.20 дал 0 CVE, архивный **Alpine 3.16 — 4 CVE** на первоначальной базе; это результаты конкретных сканов, не гарантия безопасности. На новой установке без `.local-stand/cve.json` CVE остаётся выключен. ИИ требует отдельной настройки провайдера/согласия; host/runtime capture не включены.

Аккаунты/отчёты сохраняются в отдельных volumes `dip-local-full_auth_accounts` и `dip-local-full_scan_ledger`. Подпись локального API сохраняется в игнорируемом `.local-stand/scan-jwt`; файл не печатается и не вращается при рестарте. Не удаляйте его или volumes ради перезапуска. Launcher не читает private env и не изменяет старый project `dip-auth-stand`/HOLD. Стенд доступен только через loopback; не публикуйте его в сеть.

## Новый расширенный image-only профиль

**Историческая приёмка 18.10.2026, не текущий runtime:** отдельный стенд `dip-public-images` тогда работал на http://127.0.0.1:8081; текущий runtime восстановлен и обновлён28.10, см. [актуальный итог](docs/public-finish-20261028.md). Координатор завершил guarded recovery/redeploy с проверенными quiescent SQLite backups и сохранением аккаунтов, истории, JWT и volumes этого public-стенда; исходный public HOLD архивирован. Старый **8080 остаётся отдельным legacy-профилем**, не изменён, HTTP 200 подтверждён координатором. Это не снятие иных исторических HOLD и не перенос данных между стендами.

После отдельно проверенного восстановления 8081 не нужно повторять launcher/recovery для обычного использования. Откройте **отдельный browser profile или выделенный incognito context**, перейдите на http://127.0.0.1:8081/register и создайте **новый аккаунт** с паролем от 12 символов. Cookies одного hostname не разделяются номером порта: не используйте в этом же context сессию 8080. Затем откройте http://127.0.0.1:8081/scans/new, вручную введите один из canonical references:

```text
registry-1.docker.io/library/debian:bookworm-slim
registry-1.docker.io/library/node:22.14.0-alpine3.21
```

Выберите Secrets, SBOM, CVE и Image config, дождитесь свежего серверного допуска, подтвердите цель/область и отправьте один запуск. Отчёт доступен в `/scans`, включая reload и повторный вход **на 8081**. Поиск — только подсказка; новый scan заново проверяет target, readiness и DB. POST 202 ещё не означает завершённую проверку.

**Исторические native browser/API/UI proofs от 18.10.2026 (не повторялись на нынешнем LLM candidate):**

| Запуск 18.10.2026, UTC | Secrets | SBOM | Уязвимости | Image config |
| --- | --- | --- | --- | --- |
| Debian `bookworm-slim`, 14:03:09.760–14:04:25.768 | checked, 0 | checked, 88; Debian 12.15 | checked, 241 всего: **236 CVE + 5 Debian TEMP advisories**, не 241 CVE | checked, 1 |
| Node `22.14.0-alpine3.21`, 14:05:06.605–14:06:18.591 | checked, 0 | checked, 217; npm 200 | checked, **158 CVE + 0 Debian TEMP** | checked, 1 |

Это результаты конкретных pinned сканов, не обещание таких же результатов для будущего tag. Проверены actual manual entry → fresh eligibility → POST → native worker → report → reload → fresh login; HTTP/OCI/scanner не подменялись. [Полная безопасная Node-квитанция](docs/public-image-node-native-20261018.json), [текущий статус и границы доказательств](docs/public-image-final-20261018.md).

Профиль `public-hub-amd64-v1` допускает **только публичные official/namespaced Docker Hub images, IMAGE и linux/amd64** поддерживаемого формата и размера — **не буквально любой образ/registry/OS**. Worker ограничен **4 GiB RAM без дополнительного swap**, CPU 1, PIDs 128 и tmpfs 2304 MiB; acquisition/archive/report limits конечны. Неподдерживаемые форматы/экосистемы, EOL, неизвестный inventory и превышение ресурсов не считаются checked/0. Entry point исследуемого образа не запускается; Docker socket worker не получает. Runtime/host/LLM этим профилем не включаются.

Public CVE использует собственные v2 state/trust. После исторического download failure выполнена отдельная успешная changed-release activation с four-store preservation: UpdatedAt `2026-10-25T19:10:35.479132794Z`, manifest `sha256:e1af977c90fb06ebf3d5123afb831b89d659e7e0a3fc6231e4f9e42d85c9ec98`. Freshness перепроверять при использовании; usable не означает fresh. Исторически public scheduler был установлен каждые6часов; **28.10 он отключён и выгружен** после повторного preservation HOLD. Не включать до квалификации refresh. Установка расписания не доказывала успешный periodic-run. Пустая staging архивирована без удаления historical evidence; прежняя причина download failure остаётся UNKNOWN. Подпись `local-db-operator-v1` — аттестация **локального оператора, не Aqua**. Старый LOCAL updater/scheduler не управляет8081; pins вручную не менять.

[Как пользоваться 8081 и читать ограничения](docs/public-image-ready-20261018.md). Два native PASS снимают прежнее утверждение «native NOT_RUN», но **не закрывают всю TASK2, полную OS/ecosystem/negative-матрицу или production acceptance**. Исторические source-only и HOLD-этапы сохраняют свои даты и доказательства.

## Быстро посмотреть только интерфейс

```sh
pnpm install --frozen-lockfile
pnpm dev
```

Откройте `/demo/scans` по адресу, напечатанному Vite. Это **fixture-режим**, без Docker и настоящего сканирования. Клиентский и административный entrypoints собираются командами `pnpm build` и `pnpm build:admin`; отдельная админка остаётся каркасом, не готовой системой управления.

## Регистрация и сессия без Docker

```sh
pnpm dev:auth
```

Откройте именно http://127.0.0.1:5173/register, задайте email и пароль не короче 12 символов, проверьте `/account`, выход и `/login`. `/demo/scans` доступен без регистрации. Нужны свободные порты 5173 и 3001; `Ctrl+C` завершает оба процесса.

Локальный launcher привязывает Vite/NestJS к loopback, проксирует только `/api/v1/auth` и хранит аккаунты в игнорируемой Git базе `.local-auth/auth.sqlite`. Он не публикует внутренний scan API. Cookie для `127.0.0.1` не переносится на `localhost`. Не копируйте базу, пароли или private env в репозиторий.

## Проверки

```sh
pnpm check                    # typecheck, lint, UI/API/broker tests, обе сборки
pnpm test:e2e                 # Chromium, управляемый Vite, без реального scanner
pnpm test:report-integration  # Chromium + настоящий временный Nest API/SQLite
```

Точечные команды: `pnpm test`, `pnpm test:api`, `pnpm test:broker`, `pnpm typecheck`, `pnpm lint`. API/broker используют зависимости из workspace; браузерным проверкам нужен установленный Chromium для Playwright. Интеграционная проверка создаёт синтетический отчёт и тестовые аккаунты во временном каталоге, работает только через loopback и закрывает браузер/API/listeners в конце. Она **не обращается к Trivy, Docker или LLM** и не принимает production deployment.

Большие Markdown/syntax chunks пока вызывают предупреждения Vite о размере >500 kB. Это известное ограничение, не скрытое увеличением порога.

## Docker-стенд

Для обычной локальной проверки используйте **`pnpm stand:local`**, описанный выше. Операционные deployment-границы: [server/deploy/README.md](server/deploy/README.md). Исторический launcher `pnpm stand:auth` предназначен для loopback `127.0.0.1:8080` и persistent volumes; **сейчас его нельзя использовать поверх сохранённого HOLD-стенда**. Новый project с пустыми volumes не восстанавливает старые данные.

На локальном browser ingress разрешён только ограниченный image scan `library/alpine`; Secrets/SBOM и CVE имеют независимые outcomes. CVE требует проверенного подписанного offline release; непроверенная/неподдерживаемая категория не означает ноль проблем. `/api/v1/scans` — внутренний JWT API, снаружи он не должен публиковаться. Режим всех локальных аккаунтов не предназначен для публичного доступа; production enrollment использует ID, не email.

OpenRouter key вводится оператором только через скрытый локальный ввод `python3 scripts/set-openrouter-key.py`. Не передавайте ключ агенту/в чат, argv или Vite env. Утилита не активирует провайдера и не выполняет запросы. Подробности: [server/README.md](server/README.md).

## Навигация по документации

- [Финальная проверка и незакрытые критерии](docs/release-readiness-20261015.md)
- [Проверки testing-задач и актуальная синхронизация Flownix](docs/testing-followup-20261016.md)
- [Архитектура](docs/architecture/README.md)
- [Backend/API](server/api/README.md)
- [Runtime subsystem](server/runtime/docs/operator-runbook.md)
- [Требования и исторические проектные решения](docs/TZ.md)

Исторические evidence/manifests фиксируют свои версии исходников и результаты. Изменение текущего кода не переписывает их хеши и не превращает прежний proof в новую runtime-квалификацию.
