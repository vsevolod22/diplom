# Чат: Chatscope и доставка сохранённого ответа

## Статус — обновлено после выкладки
**Выложен и проверен реальным UI-вопросом на8081.** Deployment `dcaa44be097ac42e33e568a7e7c86c6c`, web+api, new-healthy/lockreleased, completedAt2026-11-09T11:15:03.773Z; migrationfalse/historyMigrationnone, штатные preservation checks пройдены. Один разрешённый платный POST через UI собственного retained тестового аккаунта: HTTP200 NDJSON,6frames/3sources, thinkingObserved=true, ответ безreload, reloadpersisted, POST1/denied0/pageErrors0/mobileOverflowfalse375px. Private evidence `test-results/chat-ui-acceptance-20261109/result.json`;latencyMs51688 измеряет весь сценарий до проверкиreload, НЕ чистую latency модели. Никакого второго POST приreload. Модель остаётся ModuleAPI `gpt-5.4-mini`; upgrade и provider token streaming не реализованы.

Следующие разделы сохраняют первоначальное source/predeploy evidence; прежние слова «не выложен» и Docker unavailable — исторические, superseded этим статусом.

## Плавающее окно и Markdown — выложено 2026-11-09

Frontend-only `node scripts/deploy.mjs web --apply` завершён `new-healthy`, lock released, completedAt `2026-11-09T12:37:29.749Z`. Backend/worker/БД не пересоздавались. Postflight: ready=true, locked=false, root200, anonymous auth401.

Чат перенесён в отдельное modeless окно через React portal, с launcher, сворачиванием, Escape и восстановлением фокуса после render. Первое открытие монтирует панель; сворачивание сохраняет draft/history/inflight. Устранены чёрные цвета Chatscope на content-wrapper. Вопросы/ответы и preview используют безопасный Markdown с GFM; toolbar поддерживает выделение, списки и code. HTML/URLs/secrets, исходные byte-limit/auth/consent/transport guards не ослаблены. Краткое платное предупреждение видно постоянно; полные условия раскрываются отдельно.

Проверки: независимый source review без конкретных blockers и 233/233 scoped tests PASS; дополнительные chatBatch26/chatRecoveryDrafts 39/39 PASS. Production build PASS. Synthetic Chromium375/1280: min sampled contrast9.72:1, overflow0, draft/preview/focus PASS. Новая фактическая authenticated GET-only проверка опубликованного8081 на375/1280: сохранённые ответы видны, preview таблиц работает, draft сохраняется после minimize/reopen, Escape возвращает focus, overflow0, текст/editor rgb(232,237,245), pageErrors0, deniedRequests0. Private evidence `test-results/chat-widget-ux-20261109/live-result.json`, `live-375.png`, `live-1280.png`. Новых paid/model requests не было; отправка проверена предыдущей реальной приёмкой выше, не повторялась ради CSS.

Harness DIP-HRNS-6 v14 run `a167d483-8072-4415-8595-dcc734471e97`: четыре исходные роли завершены; final review дал результат, но шаг завершился timeout до work_complete. Это FAILED orchestration, не успешный harness run. DOC15 amendment остаётся отдельным незавершённым пунктом; native token streaming/model upgrade/full-site acceptance не заявляются.

## Реальное воспроизведение
Одна разрешённая платная попытка собственного retained тестового аккаунта на scan `305a55de-6d94-4af6-a653-2bd117e1ec85`: POST вернул HTTP502 `text/html` через 27727ms; последующий авторизованный GET истории нашёл именно отправленный mutation в состоянии completed с reply. Nginx зарегистрировал `upstream prematurely closed connection while reading response header from upstream`. Содержимое ответа, cookie и ключ не выводились. Это подтверждает ошибку доставки при успешном durable commit, но не доказывает единственную внутреннюю причину всех прежних 502.

## Изменения
- Chatscope2.1.1 / styles1.4.0 поддерживает React19; сообщения используют `Message.CustomContent`, не HTML payload. Окончательный ответ по-прежнему проходит SafeMarkdown. Мобильные пузыри и честный typing indicator; reduced motion отключает анимацию.
- Completed-only путь публикует заранее полностью проверенный конечный NDJSON документ одним `response.end(wire)` внутри свежего trusted session/report/policy/exact-head guard. Размер ограничен существующими 196608B/52frames/8192B-per-line. Логические frame/receipt/EOF схемы не меняются, `nativeProviderStream:false` сохраняется.
- Вместо повторного чтения всех authority stores для каждого маленького completed frame выполняется одна guarded publication, без await внутри транзакции. Сокетный finish всё ещё ограничен5s; lease удерживается до finish/ошибки/abort и освобождается один раз. Failure/duplicate writer сохраняет прежние per-write/post-drain guards.
- Устаревшие session/report/history на момент единственной publication запрещают весь ответ. Отзыв ПОСЛЕ окончания этой атомарной отправки не отзывает уже отправленные байты, как и у completed JSON.
- UI отличает nonJSON gateway502/503/504 от явного typed failed frame. Только при таком transport отказе или timeout выполняется один GET-only reconciliation. Требуются та же session/preferences/policy/report, epoch, exact revision+2, mutationId, question, completed turn и источники из авторизованного полного отчёта. Ответ берётся только из заново проверенной durable истории. Не создаётся второй POST, receipt или нулевое потребление. При несовпадении ответ скрывается. Abort, смена владельца, ошибочный NDJSON и явный provider failed frame не превращаются в success.

## Проверки
- Frontend/client:104PASS после отдельного исправления первоначальной регрессии — reconciliation было слишком широким и принимало typed failed frames; теперь только transport gateway failure/timeout.
- Backend delivery:37PASS. Контроль51-frame документа с150ms проверкой на frame воспроизводит исчерпание5s у прежнего writer; новый completed writer выполняет один guard и сохраняет wire. Есть stale authority/abort/deadline и stalled finish cleanup.
- Frontend/API typecheck, scoped frontend ESLint, production build PASS. Существующее предупреждение больших chunks не скрывалось.
- Historical r5 browser runner отказал на устаревшем source hash до browser acceptance. Пины не обновлялись; это НЕ browser PASS.
- Актуальный cookie/Nest/controller HTTP regression проверяется отдельно; итог зафиксирован в комментарии Flownix, не выводится из unit PASS.

## Блокировки выкладки
Read-only `node scripts/deploy.mjs app --services web,api` вернул DEPLOY_PREFLIGHT до lock/fence. `docker version` и API `docker logs` не отвечают в пределах timeout; диск имел14GiB свободного пространства. Docker lifecycle/reset/volume cleanup/apply не выполнялись,8080 не затронут. Нужен отвечающий Docker Engine, затем normal read-only preflight, одна web+api выкладка и реальный UI chat POST/reload acceptance.

## Flownix и дальнейшая работа
DIP-HRNS-6 v12 run `723b7d27-13c8-40f0-ae4e-cec175fa999e` создан для четырёх Sol6.1 ролей. Все spawn остановлены usage limit, независимый review не состоялся. Основной агент выполнил этот source increment сам. Не выдавать run за completed independent review.

Перед полной приёмкой нужен full-body delta DIP-DOC-15, явно уточняющий atomic completed publication и отдельную GET-only recovery после transport failure. Старое требование per-frame проверки не удалять молча. `$5` lifetime budget, UNKNOWN liabilities, модели/тарифы/секреты и БД не менялись.
