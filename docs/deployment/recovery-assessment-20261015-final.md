# Final recovery assessment — 2026-10-15

## Решение

**HOLD сохранить. Безопасное восстановление существующего стенда сейчас НЕ доказано; необратимая потеря всех пользовательских данных также НЕ установлена.** Запуск старых приложений, повтор R4/новый R5, удаление holder или reset не являются допустимым способом выяснить состояние данных.

Это read-only recovery assessment, не execution approval, не deployment/PRE certification и не закрытие продуктовых критериев. Единственная запись этого прохода — данный новый документ. Runtime, контроллеры, frozen scripts, private leaf contents, lock/HOLD, tracker/spec и Git index/HEAD не изменялись.

Исходный checkout: `/Users/vsevolod/Documents/oldstartup/diplom`, HEAD `636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7`; перед оценкой `git status --short` был пустым. Параллельная сборка новых образов не является восстановлением стенда или свидетельством сохранности его данных.

## Основания и пределы наблюдения

Приоритет ограничений: `hold-handoff-20261015.md`, особенно строки 47–60. Более позднее наблюдение состояния взято из `../release-readiness-20261015.md:75–81`: holder `207709…5380e4` уже EXITED, в том snapshot нет running/paused контейнеров. Это supersedes исторический PAUSED, но не объясняет переход и не удостоверяет backup.

### Что выполнено в этом проходе

1. Прочитаны публичные handoff/readiness/review документы и относящиеся к recovery участки controller/helper/diagnostic/test source. Никакой controller/helper/test не импортировался и не исполнялся.
2. **Один новый ограниченный Docker metadata request** для шести точных IDs ниже. Использован явный локальный socket `unix:///Users/vsevolod/.docker/run/docker.sock`, изолированный Python `-I -B`, один CLI без retry; внутренний deadline 18 секунд, внешний 23 секунды, stdout cap 32 KiB, aggregate stdout/stderr cap 64 KiB. Проекция запрашивала только ID/image, выбранные lifecycle flags/exit/timestamps, actual Mounts и HostConfig.Tmpfs. Не запрашивались Env, labels, commands, logs, health output или полный inspect. Ничего не выводилось до проверки всего ответа.
3. Запрос завершился exit 1 с единственным закрытым результатом `{"ok":false,"observation":"REFUSED_NO_RAW_OUTPUT","retry":false}`. **Никакие STATE/MOUNTS значения из него не приняты и не опубликованы.** Причина отказа этим receipt не различается: нельзя приписать её Docker, sandbox, отсутствующему ID или проверке формы ответа. Runtime query не повторялся.
4. Независимая metadata-only проверка двух точных host roots и пяти известных coordination pairs: только no-follow directory FDs, `stat(..., follow_symlinks=False)`/`fstat`, контроль ancestry/stability, без directory enumeration, открытия leaf-файлов, хеширования private material, fsync или записей. Deadline 10 секунд, внешний 15 секунд, output cap 8 KiB. Результат ниже. Ни одна lock-пара фактически не была обследована после отказа/отсутствия root.
5. Побайтно хешированы только шесть явно выбранных публичных source/script файлов; никакие private recovery/Env/DB/backup bytes не читались.

Не запускались frozen diagnostics, тесты, HTTP/provider/scanner, SQL, compose, start/stop/restart/unpause/exec/cp/rm/prune или процедуры восстановления. Не создавались новые stand/volumes/actors. Отдельная свежая full-container writer fence не выполнялась.

### Точные targets единственного Docker request

| Роль | Полный ID |
|---|---|
| Retained holder | `207709f0f2992532af3331e0e2b38878c08a8d157ad074956f78c895aa5380e4` |
| Original API | `5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec` |
| Original worker | `016c41e7b3eabcbb08903bbc3c54d657ed92c22813e47fa37d444cb448602b44` |
| Original web | `b84245ef672d172d5513971a57ea91469800846cdf6c59bedceb006b06caa4f4` |
| Original egress | `2850e2d03d0681482727f7b5d658961ef9ef2aa829b63473f36d8ed3c63f3d35` |
| Original llm-egress | `f64639115f21233277ac52db2bd5ceda495203511da87896ff996e8c1ce3a68a` |

**Свежие состояния/mount bindings этих targets остаются NOT_OBSERVED в данном проходе.** Не следует превращать запрос в успешную повторную инвентаризацию или считать отсутствие выданных mounts отсутствием томов.

### Host coordination metadata receipt

Наблюдение `2026-10-15T19:26:03.720049+00:00`:

| Точный root | Закрытый результат | Интерпретация |
|---|---|---|
| `/Users/vsevolod/Documents/oldstartup/diplom/.local-auth` | `PRIVATE_ROOT_METADATA_REFUSED`, pairs `[]` | Traversal дошёл до root, но root не прошёл совокупную проверку directory/owner/group/0700. Какой именно predicate не совпал, не экспортировано. Не доказано наличие или отсутствие любой lock-пары. |
| `/Users/vsevolod/Documents/startup/diplom/.local-auth` | `ANCESTOR_OR_ROOT_ABSENT`, pairs `[]` | Один из компонентов точного исторического пути отсутствовал. Какой именно — не экспортировано. Это не доказательство удаления private данных, не поиск другого местонахождения и не разрешение fallback на текущий checkout. |

Allowlist, который не был пройден из-за root boundary: `.trivy-refresh.lock`, `.key-preservation-reconcile.lock`, `.key-preservation-reconcile-r2.lock`, `.key-preservation-reconcile-r3.lock`, `.key-preservation-reconcile-r4.lock`, в каждом только metadata имени `KEY_ACTIVATION_HOLD.json`. Root или lock permissions не исправлялись; symlink не следовались; marker contents не открывались.

`ok:true` этой host-проверки означает успешную выдачу закрытых классификаций, **не** safe custody/complete inventory. Число существующих HOLD-пар сейчас не установлено. Handoff допускает пять исторических пар; все они продолжают считаться защищёнными от удаления/усыновления.

## Что доказывает публичный source, а что — нет

Пути в этом разделе относительно repository root.

| Source | Установленное свойство / ограничение |
|---|---|
| `server/deploy/trust/recreate_openrouter_key.py:428–433,2533–2589` | Holder использует `setTimeout(()=>{},240000)`. `/backup` — tmpfs 2 GiB, `/tmp` — tmpfs 128 MiB; source stores подключаются отдельно. В migration mode original auth/data mounts предусмотрены RW, даже если capture читает originals без SQLite. Это source expectation, не свежая аттестация retained actor. |
| Controller `:3156–3209` | Порядок: capture → export PRE → plan → durable plan export/rechecks → apply → POST/compare/compatibility. Исторический R4 `export_pre` failure precedes plan/apply/replacements **в этом controlled path**. Это не независимый аудит всех writers/всех прежних попыток. |
| `server/deploy/trust/sqlite_state_snapshot.mjs:85–164,934–966` | Capture копирует originals через O_RDONLY/O_NOFOLLOW; SQLite recovery/sealing выполняются на working/sealed copies. Сохраняются raw trees и sidecars, затем manifest. Fsync внутри `/backup` не превращает tmpfs в durable host export. |
| Controller `:2619–2716` | Export требует holder inventory до и после cp, host inventory/equality, manifest/admission, directory fsync и final qualification/fence до certification. Успешный capture не заменяет эти шаги. |
| Controller `:992–1056` | Manifest проверяет raw/sealed records; **working files не имеют manifest hashes**, их binding обеспечивается отдельным same-holder inventory до/после copy. Даже найденный manifest сам по себе не восстанавливает это доказательство. |
| Controller `:2822–2867` | Fail-stop пытается pause только qualified own holder; намеренно не останавливает/удаляет его из-за риска потери sole tmpfs. Best effort не доказывает успешный pause, непрерывное удержание или причину последующего EXITED. |
| `server/deploy/trust/diagnose_retained_pre.py:363–395` | Последний metadata-only mode проверяет именно PAUSED/running=true/paused=true на `M_IDENTITY`, до host metadata. На EXITED он откажет, а не обследует host PRE. |
| Diagnostic `:43–44,166–185`; controller `:497,1801–1803` | Frozen incident root — `/Users/vsevolod/Documents/startup/diplom`, не нынешний `oldstartup/diplom`. Есть path/source/coordination gates. Запуск из нового cwd или смена pins не является переносом разрешения. |
| Diagnostic `:398–427` и handoff `:56` | SPENT diagnostic отказал на `PRE_MANIFEST_SEAL`: bucket включает отсутствие/type/size/metadata/read-seal/hash mismatch. Причина не локализована. Нельзя заключать «только права», «Docker cp вложил pre/pre», «manifest отсутствует» или «данные целы». |
| Controller `:2095–2167,2325–2415` | Даже успешные metadata выбранных шести контейнеров не были бы full writer fence: нужны bounded census всех контейнеров, daemon/volume binding, protected-store alias classification и exclusive maintenance. Текущий stopped-reconciliation также ожидает running egress; более поздний all-stopped snapshot этому не соответствует. |

### Значение EXITED и tmpfs

Обычный Docker tmpfs не является сохраняемым слоем контейнера/томом и не сохраняет содержимое после остановки. Поэтому для последнего наблюдавшегося EXITED holder **нет обоснованного стандартного пути «start и забрать прежний /backup»**: start не восстанавливает прежнюю tmpfs. Container filesystem export/copy/commit также нельзя считать backup исчезнувшего tmpfs; lifecycle actions здесь запрещены независимо от технической доступности команды.

Это архитектурный риск, **не forensic-свидетельство того, какие bytes фактически сохранились или были утрачены**. Причина exit, точное состояние VM, наличие ранее завершённого host PRE или внешнего snapshot не установлены. Не обещать восстановление tmpfs и не объявлять все persistent stores потерянными. Original named volumes и `/backup` — разные места хранения; потеря PRE не тождественна потере originals.

Source-defined original volume names: `dip-auth-stand_auth_accounts` и `dip-auth-stand_scan_ledger` (`recreate_openrouter_key.py:404–409`). В этом проходе их существование, mountpoints, содержимое, versions и integrity не аттестованы. Не открывать предполагаемые `/var/lib/docker/volumes/...` пути на macOS host: это не установленное отображение Docker Desktop VM storage.

## Матрица неопределённости сохранности

| Вопрос | Сейчас |
|---|---|
| Все ли original stores существуют и содержат пользовательские данные? | NOT_OBSERVED; имена из source не являются inventory. |
| Есть ли полный host PRE/другой durable backup, где он и чей он? | NOT_OBSERVED; root classifications не ответили на это. |
| Можно ли получить прежний sole PRE из EXITED holder? | Не установлено; обычная tmpfs stop semantics против такого предположения. Holder всё равно не трогать. |
| Менял ли R4 originals через apply-migration? | По зафиксированному failure/source order этот этап не достигнут в R4 path; независимая фактическая проверка stores отсутствует. |
| Actual ledger 13 или 14; auth/quota versions/integrity? | Неизвестно. Не использовать app startup как probe. |
| Доказано ли сохранение всех исходных rows/objects/sidecars относительно исторического PRE? | Нет. Новый snapshot, даже полный, сам по себе не восстановит потерянное историческое доказательство. |
| Можно ли безопасно поднять existing stand сейчас? | Нет достаточного основания для approval. Conditional rescue возможен, если подтвердятся persistent originals и проверенные durable copies. |

## Конкретная rescue-последовательность — предложена, НЕ разрешена к исполнению

### 0. Сохранить incident boundary

- Оставить все original containers/volumes/images, retained holder `207709…`, CREATED `d943…`, private host trees и все HOLD/locks без изменений. Прежнее согласие на `4dc…` не распространяется на `207709…`.
- Не запускать/перезапускать Docker Desktop/VM или приложения ради диагностики: restart policies и mount lifecycle требуют отдельной оценки. Не выполнять prune, rm, reset/init, chmod/rename/repair/adopt locks, blind restore/rollback, recapture или R5.
- Не включать refresh/schedules/provider/history; historical scanner331 и history362/363 не повторять. Никакого нового пустого stand как замены данных.
- Сборка образов не должна автоматически создавать стенд, поднимать services или занимать protected volumes. Общие RAM/disk/Engine остаются shared ресурсами; build PASS не даёт recovery authority.

### 1. Следующая необходимая отдельно reviewed операция: новый read-only custody/location observer

**Это ближайший шаг, не ещё одна production attempt.** Нужны независимые correctness/security review точного нового source/literal и явное решение координатора об одном запуске. Не повторять отказавший observer этого прохода и не менять frozen diagnostic для обхода PAUSED/path gates.

Предмет review:

1. Fresh bounded exact-ID lifecycle/mount projection, корректно классифицирующая EXITED/PAUSED/CREATED и nullable metadata, без raw exception/log/Env/health output. Конечные error categories должны различать transport, CLI и shape refusal без выдачи private values. Никаких fallback IDs, retries или lifecycle.
2. Точное подтверждение identity/location двух existing named volumes и их связи с originals; при необходимости отдельно ограниченный all-container protected-writer census. Read-only metadata не разрешает остановить найденного writer и не доказывает continuous exclusion.
3. Отдельная безопасная классификация root metadata mismatch и historical-path absence. Не создавать прежний путь, не symlink его на новый, не chmod `.local-auth`, не repin controller ради прохождения. Relocation/copy/root identity должны быть установлены, а не выведены из совпадения имён.
4. Если отдельно разрешён ровно один incident label как selector, держать его значение внутри observer, проверять literal basename/ancestry и не считать label ownership. Только fixed host PRE/layout/manifest **metadata**, nofollow, без leaf reads/hash, recurse или raw listing. При unsafe/missing/ambiguous path — закрытый STOP, а не поиск по всему диску.
5. Ограничить calls/bytes/deadline и итоговый receipt; при любом отказе остановиться без compensating action. Выдать только accepted observations/NOT_OBSERVED, а не «recovery succeeded».

Сейчас этот observer не реализован и не approved. Даже его успешный metadata-result не даст backup certification: для этого неизбежно потребуется отдельная операция с private bytes внутри защищённого процесса.

### 2. Фактическое durable-сохранение — отдельная новая граница разрешения

После установления custody/location, до первого application/SQLite RW на originals, отдельно согласовать операцию preservation-only. Она **не входит** в текущий запрет на чтение private payload и не выполнялась здесь.

Предпочтительный результат: immutable/private durable evidence copy текущих original volumes и обнаруженного host recovery material с полной raw-layout/sidecar сохранностью, закрытым внутренним inventory и проверкой destination; затем проверка SQLite только на производных копиях. Не читать/печатать Env/keys/DB/backup содержимое агентскими tools.

- Требуются fresh writer exclusion, отсутствие auto-start/сchedulers, capacity и точная binding обоих existing volumes. При недоказанной целостности/исключении writers — STOP, не application probe.
- Для copier/sandbox review установить network-none, no app entrypoint/import, RO original mounts, no SQL на originals, отдельный durable destination (не только tmpfs), exclusive creation/no overwrite, bounded resources/time, безопасную обработку links/owner/modes и fsync/readback verification. RO named-volume mount — проектное требование будущего reviewed copier, не уже проверенная возможность или готовая команда.
- Сохранять весь scope состояния и sidecars, не только MAIN `.sqlite`; оставлять оригиналы неизменными. Сначала durable raw acquisition, потом recovery/validation на disposable clones. Ключи/secret settings остаются внутри отдельно разрешённого private workflow; не добавлять их в публичный receipt.
- При подходящем operator-managed offline snapshot backing storage Docker Desktop он может дополнительно сохранить persistent evidence, но его точный путь/согласованность/поддерживаемость не проверены. Не копировать live backing disk как гарантированно согласованный backup и не останавливать VM ради такого копирования в текущем scope. Такой snapshot также не возвращает уже исчезнувшую tmpfs.
- Если старый PRE отсутствует/неполон, новую acquisition маркировать **новым rescue baseline текущих originals**, не историческим R4 PRE. Это требует отдельного информированного решения о разрыве historical all-state proof; не молчаливой recapture/подмены baseline.
- Если нужные persistent originals не найдены либо копия не проходит проверки, остановиться: отдельный operator forensic/backup-location review. Пустой init/new project/new volumes не являются recovery.

Таким образом, первая реально сохраняющая данные операция будет **записью verified durable private copies**, а не снятием HOLD. Её реализация/исполнение требуют новой независимой проверки и согласия; в этом документе нет готовой команды на private data acquisition.

### 3. Recovery/deployment только после verified copies и отдельного решения

- На производных копиях установить actual schemas/versions, integrity и исходную совместимость; public source expectations не заменяют actual observations. Разделить допустимую additive migration и обычные startup/queue writes.
- OLD worker не годится как безопасный fallback: `old-worker-startup-binding-20261015.md:32–55` фиксирует RW/WAL до version gate, ceiling 13 и неполный startup/import closure. Unknown ledger не считать 13; при 14 OLD worker source-incompatible. Даже при 13 startup не no-write.
- Сверить новые image IDs, полный startup effects/source closure, compiled deployment/topology и release evidence с фактическими сборками. Source aggregate/pins из исторического R4 не переносить на новые образы. Существующий controller не имеет reviewed rescue/adoption пути и сохраняет старые path/image/running-egress gates; не обходить их флагами.
- Подготовить новый отдельно reviewed recovery plan: custody/backup receipts → проверенный migration plan на копиях → отдельное разрешение original writes → POST/all-state comparison → staged API/worker readiness при закрытом ingress → web/anonymous/auth persistence checks. Никаких автоматических retry/rollback/cleanup после неопределённости.
- Historical lock reconciliation — отдельная операция с собственным review/authority, **не** условие «сначала удалить locks, чтобы всё заработало». Этот assessment ни одну pair не усыновляет и не разрешает удалять даже после успешного deployment.
- Provider activation, native history, scanner production acceptance и schedules — отдельные opt-in/приёмочные границы, не побочный эффект rescue.

## Что остаётся продуктовым blocker после rescue

`../release-readiness-20261015.md:56–85` не позволяет объявить продукт завершённым по source/unit/build PASS. Recovery закрывает только предпосылку безопасной runtime-проверки. По-прежнему отдельно нужны выбранная production topology/runtime/enrollment qualification, host/domain/TLS/firewall и persistence/backup-restore acceptance, согласованные scanner/runtime/SSE/reconnect/cancel/rotation проверки без повтора запрещённых исторических proofs, native history/provider ingress acceptance, ручная VoiceOver/NVDA/QA/performance проверка и tracker/spec reconciliation после доступности backend. В частности TASK41 local draft не является applied delta. В этом проходе backend не опрашивался, spec/status не менялись и ни один критерий автоматически не закрыт.

## Проверенные публичные hashes этого checkout

Это текущая source-identification, **не новое разрешение исполнения** и не обновление старых evidence seals.

| Файл | SHA-256 |
|---|---|
| `server/deploy/trust/recreate_openrouter_key.py` | `76153d2cd7d0452c14149a367cde4bb934d973380a7e10e22ebb798f95893857` |
| `server/deploy/trust/test_recreate_openrouter_key.py` | `15b0460d1faefa31112f67cbfa86cd1d0db90046ecb2f74b110ba6e90629ac60` |
| `server/deploy/trust/diagnose_retained_pre.py` | `44b2b7fc61c63df2fd7e9a7fb2331b7c905be88b6a307924b4d5d2a7b970ea91` |
| `server/deploy/trust/test_diagnose_retained_pre.py` | `da42b17f35c50649d1e94e75fe2c94089d9b68f04bfbcc9d63ca9b2fccf2c446` |
| `server/deploy/trust/sqlite_state_snapshot.mjs` | `323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee` |
| `docs/deployment/retained-pre-metadata-20261015.sh` | `7076fd4d742aa04119dde3b444a726fe0d07b210de6df4136494cf865825406f` |

**Итог координатору:** сохранность existing persistent data потенциально ещё можно обеспечить, но «без риска сейчас поднять старый стенд» не обосновано. Не потерять оставшиеся originals/material важнее восстановления доступности. Ближайшая граница — independently reviewed новый read-only custody/location observer; первая data-preserving mutation — отдельно согласованная durable acquisition, не старт holder/приложений. Любое обещание historical PRE recovery, integrity или deployment success на текущих фактах было бы недостоверным.
