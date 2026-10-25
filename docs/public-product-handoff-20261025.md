# Public8081 — историческая передача до restart/recovery25.10

> **SUPERSEDED:** после явного разрешения владельца выполнен один Docker Desktop restart и одно exact continuation — actual READY/exit0, public8081 и protected8080 HTTP200, четыре stores/JWT сохранены, operation evidence архивированы. Fresh native scan completed, foreign browser404/UI denial PASS; chat502/translation429 BLOCKED, cancel attempt доsubmission не квалифицирован, publicCVEdownload failed доfence, schedulerpending. Актуальная передача: [public-recovery-ready-20261025.md](public-recovery-ready-20261025.md). Token/checker/continue для audit2c9 consumed, не повторять. Ниже сохранён исходный pre-restart HOLD handoff, **не текущая operational инструкция**.

Этот документ superseded READY от22.10 на момент своей первой записи; теперь сам superseded новым READY receipt. Исторические receipts/FAIL не переписываются.

## Фактический статус

- Ветка/upstream: `feat/dip-task-30-21st-components` / `origin/feat/dip-task-30-21st-components`; baseline перед этим инкрементом `b73c28a65dc482809de5bc066ef07ed87cf57def`.
- До maintenance оба адреса8081/8080 отвечали HTTP200. Public metadata независимо прошли:7services/6networks, APIhealthy UID65532, API-only readonly/nocopy key-volume, worker4GiB без дополнительного swap/CPU1/PIDs128, раздельные egress и immutable pins.
- Координатор выполнил **один** normal submission `node scripts/public-llm-stand.mjs up --ack-public-maintenance --build`. Новая операция **`deploy-2c9ed08b8269264b09bf14eb6189a649`** остановилась на **`build-submit-worker`**, сохранённая category **`unclassified`**. Точная причина worker build не установлена. Buildx metadata подтверждает завершённый API build, но не устанавливает причину worker refusal.
- После отказа actual probes:8081 HTTP000 (нет HTTP-ответа),8080 HTTP500. Причинная связь деградации8080 с build **не установлена**. Protected8080 lifecycle/containers/данные координатором не изменялись.
- Fresh read-only checker нового narrow recovery отказал **до intent/submission**: Docker `image inspect` pinned `auth-volume-init` image вернул **blob input/output error**. Это установленный metadata/storage-I/O отказ, **не доказательство исходной причины worker build**, не missing-image exception и не разрешение обходить metadata.
- Docker Desktop restart запрошен у владельца отдельно: он затронет protected8080. **Не выполнен.** Ничего не prune/delete/reset/unlock. Нет новых provider calls, quota refund/reset или повторного deployment submission.

## Сохранение состояния

Original lock содержит `build-checkpoint.json`, `build-failure.json`, `helper-fenced.json`, `llm-candidate/`, `mutation.json`. Original audit содержит `fenced/core` и `fenced/llm`; evidence/backups не перезаписывались и не удалялись.

До build штатный launcher создал оригинальный four-store fenced backup и durable pre-build checkpoint. Новый read-only preparer смог проверить original exported backups/fingerprints против checkpoint до metadata refusal. **Fresh current-store comparison НЕ выполнен**: он обязан происходить в network-none helper до любого нового build/init/application start. Наличие оригинальных backup не заменяет final live preservation acceptance.

Original API image после успешного API build может быть недоступен по прежнему immutable ID. Нельзя start/exec original с отсутствующей image metadata или сертифицировать её как present. Retained init image вернул именно I/O, не подтверждённое отсутствие. Его metadata requirement не ослаблен.

## Проверенная source-работа

1. Backend transport/provider/history/filter различают finite provider rate-limit/auth/unavailable; bounded `providerFailure.{kind,status,retryAfterSeconds?}` без raw payload/message. Retry hint информационный, без autoresend. Provider401 не подменяет browser-session401. NDJSON error-only либо usage→error сохраняет receipt/accounting/EOF guards; неизвестное dispatched consumption не прощается.
2. Frontend принимает exact JSON/NDJSON producer wire, показывает понятные русские ошибки, сохраняет manual recovery. Advisory translation имеет45s whole-operation deadline, отменяет публикацию late reply и требует новое consent. Оригинал сохраняется.
3. `russian-prose-v2` входит в policy hash; prompts требуют русский human text с неизменными техническими именами и CVE/TEMP. Нужен свежий context/consent. Exact per-field identifiers сохраняются.
4. Browser runners допускают только необходимые точные GET, отдельный translation-only mode и новые exclusive sanitized artifacts; корректно сохраняют finite provider statuses/hints. Новых live запусков после этого fix **нет**.
5. Новый отдельный entry `scripts/public-llm-existing-build-continuation.mjs` поддерживает **только этот exact new audit/prefix**, existing seven-service/key/four-store state. Не исторический first-enable route и не generic unlock. Durable baseline/original exports; bounded full18-module execution closure +403source files; bytes/inodes; runtime/pins/key authority; stale-token refusal; fresh network-none comparison до build; no initializer/writable check helper; candidate API для later snapshots; append-only continuation evidence и archive entire lock на успехе. StorageIO fail-closed outranks missing-image hints. Исторический loader whitelist не ослаблен.

Independent source review: P1/P2 в scoped wire/recovery review не найдены. Source GO **не runtime review token, не successful continuation**.

## Разумная финальная валидация

| Проверка | Actual результат текущего инкремента |
|---|---|
| `pnpm test:api` |1346/1346PASS,0failed/0cancelled, один final run |
| `pnpm test` |742/742PASS,32files, один final run |
| API typecheck |PASS |
| Frontend typecheck |PASS |
| Root `pnpm lint` |PASS, включая новый recovery source |
| Main/admin builds |PASS; Vite >500kB chunk warning остаётся |
| Новые recovery policy/fixture/source tests |88/88PASS, независимо повторены reviewer |
| Existing selected launcher regressions |author17PASS; independent reviewer15PASS, scoped not fullsuite |
| Browser runner offline |59PASS, не native acceptance |
| Independent producer/parser wire |131targetedPASS +22positive/5negative probes |

Предыдущие suite/SSE/paging intermittencies в этих final fullruns не воспроизвелись; **не объявлены исправленными**. Recovery tests используют fixtures/policy/source boundaries, не доказывают native full recovery. Новая native/browser acceptance **NOT_RUN**: см. `public-final-browser-20261025.md`.

## LLM / перевод — честная граница

Public key уже provisioned API-only readonly; значения/env не читать и повторно не импортировать. Ранее auth/key HTTP200, но completion429; точная внешняя причина неизвестна. Fixed profile **OpenRouter `xingchen-agi/xing4.0-29b-a4b:free` → `phala`**, free-only/ZDR/no fallback неизменен. Успешная реальная generation/ru translation по-прежнему **UNVERIFIED**. Adapter `stream=false`: NDJSON доставляет завершённый ответ, не native token streaming.

Known frozen translation limitations: `#` запрещает корректный C# в reply; script-ratio может отвергнуть Latin-heavy technical title; domain-like guard может исключить Node.js-only field. Это локальные reproduced ограничения, не установленная причина прежнего provider refusal. Schema/кириллица не доказывают semantic quality. No persistent translation cache, originals/provenance/unknown-language/CVE-vs-TEMP не заменяются.

## Flownix и настоящая параллельность

Project `520a0059-d0f2-4f86-8d93-fc15035a5715`, fresh policy full/strict/approval=false/spec_first=false/parallel/direct.

Два настоящих харнесса с шестью real spawn agents, формальным claim/context/work-complete:
- DIP-HRNS-6 run `94e26691-ef66-463d-adaa-1992ea27cf4f`: три source verification lanes; completed.
- DIP-HRNS-7 run `7aa358d1-d67b-4ddb-b8c0-4c560c16b8f4`: browser/security/spec; completed **с blocked browser outcome**, не app PASS. Spec work snapshot был prepared; последующее apply отдельно разрешено и записано в task.

Дополнительно real agents независимо реализовали/проверили новый recovery/test scope. Их offline evidence не выдаётся за live execution.

Applied TASK42-sourced full deltas:
- DOC16v2→v3: `1eef696c-4cdd-4174-bbd9-bebd24447e21`;
- DOC15v2→v3: `501162c5-2d7e-4695-8dd1-33dd52b17c34`.

Fresh full-base/delta comparison, validation и post-apply `valid:true`; no removed/renamed requirements. Spec apply **не deployment**. New fullbodies/receipts: `public-final-spec-*-20261025.md`. Evidence errata отзывают невоспроизведённый mismatch claim; historical JSON/MD original pairs совпали с HEAD и не изменены.

**Новых task done нет.** TASK42 остаётся blocked; принятые14/16/21/39/40/41 не переоткрывались. TASK2/3/4/9 не закрывать по частичным proofs, родителей каскадом не закрывать.

## Следующий безопасный шаг

1. Получить явное разрешение владельца на **один restart Docker Desktop без factory reset/удаления данных**, поскольку protected8080 затронется. Restart не гарантирует исправление storage I/O; при сохраняющемся I/O нужна диагностика Docker storage, не forced image deletion.
2. После разрешённого restart сначала safe probes/metadata, **не запускайте normal up повторно** и не удаляйте lock. Source/execution closure нового recovery перечитать и независимо сверить; не редактировать во время actual checked continuation.
3. Только fresh read-only checker:

```sh
node scripts/public-llm-existing-build-continuation.mjs check-existing-build --audit deploy-2c9ed08b8269264b09bf14eb6189a649
```

Он читает утверждённые settings/JWT и оригинальные private backup copies внутри процесса, но не provider key; не build/start/exec/init и не writes original evidence. Вывод — finite summary/token либо конечный refusal. **Текущего успешного runtime token нет.**

4. Только после успешного fresh checker, актуального independent review и owner-approved operational window допустима ровно одна `continue-existing-build` с **только что полученным** `--review` и acknowledgements `--ack-reviewed-current-source --ack-retire-only-unavailable-peers`. Не подставлять source-freeze digest вместо token. No token здесь намеренно не выдуман. Новый отказ сохраняет HOLD; нет blindretry/unlock/старогоrecovery.
5. После actualREADY отдельно browser disposableaccount→manualHub linux/amd64 scan→real report/counts/pages/cancel/history/freshlogin/foreign denial; explicitconsent→2chat replies+ru translation в fixedprofile. Не сохранять private conversations/payloads/screenshots. No paid fallback/autoretry/refund.
6. В отдельном maintenance window реальный changed publicCVE refresh с four-store preservation, затем separate public scheduler install/status. Не старый8080 updater. Старый public UpdatedAt20.10 stale-but-usable до03.11; перепроверять current freshness. Local operator signature не Aqua.

8080/dip-local-full/dip-auth-stand/.local-auth/retained holders/backups/keys защищены. Никаких global prune, volume delete, reset/clean/revert, arbitrary holder exec или чтения fullEnv. Cleanup не выполнялся во время unresolved storage-I/O/HOLD.
