# Продолжение локального image-only продукта — 2026-10-21

> **SUPERSEDED для текущего lifecycle:** после этого handoff выполнен один reviewed continuation, возник новый **HOLD phase=initialize**. Старые checker/continue команды ниже больше неприменимы. Актуальный итог, never-started initializer, source fixes и необходимые новые review/authorization: [public-product-status-20261021.md](public-product-status-20261021.md). Original backups/lock сохранены; 8081 HTTP000, 8080 HTTP200; provider key отсутствует. Ниже сохранён исторический handoff без переписывания прежних evidence.

## Актуальная точка передачи

На проверке `2026-10-21T18:46:42Z`:

- Repo `/Users/vsevolod/Documents/oldstartup/diplom`, ветка `feat/dip-task-30-21st-components`.
- HEAD остаётся `7c47bc5e5b09419378e70c80d59a8c310f662261`, upstream `origin/feat/dip-task-30-21st-components`.
- Значительная новая работа MODIFIED/UNTRACKED, не закоммичена и не отправлена. При старте этой сессии дерево было чистым; всё текущее дерево всё равно сверить перед работой, не reset/clean/stash чужой работы.
- **8081 HTTP000, НЕ работает:** новая public LLM maintenance остановилась на build HOLD. Web/API/worker остановлены clean exit0; registry egress работает по диагностике автора. Это не прежний архивированный recovery.
- **8080 HTTP200**, lifecycle/данные старого окружения не изменялись этой работой.
- Public LLM config metadata: config present=true, key present=false. Реальная генерация НЕ проверена и НЕ работает как принятый сценарий.
- Flownix DIP `520a0059-d0f2-4f86-8d93-fc15035a5715`; fresh policy была full/strict/approval=false/spec_first=false/parallel/direct. При продолжении перечитать.

## Что реализовано и проверено

### CVE public8081

Default public refresh/provision/scheduler CLI с concrete shared-lock/snapshot bridge реализованы и прошли независимый re-review. Фактически выполнены:

1. `public-cve-provision.mjs prepare`: новая public-owned копия прежних signed public bytes без переподписания; dedicated future refresh signer, без чтения старого private key.
2. v1→v2 guarded migration: API/worker replacement, original web resume после preservation, PASS.
3. fresh upstream stage и настоящая guarded activation: PASS, прежние accounts/reports/JWT сохранены проверками. Это native maintenance, не новый scanner findings proof.

Активный public v2 release на последнем чтении:

- manifest `sha256:5903d201b3dc68dda334b9a9397ed51bd7956d834f43ab4edae6844a18912ced`;
- UpdatedAt `2026-10-20T19:12:26.430296739Z`;
- NextUpdate `2026-10-21T19:12:26.430296358Z`;
- DownloadedAt `2026-10-20T22:54:18.765315Z`;
- usableUntil UpdatedAt+14d: `2026-11-03T19:12:26.430296739Z`;
- signer `local-db-operator-v1`, **локальная аттестация, не Aqua publisher signature**.

Время/статус свежести перечитать при использовании; usable не равно fresh. Public scheduler ещё НЕ установлен/не квалифицирован нативно. LLM-enabled preservation/overlay поддержаны source/tests, реальный post-LLM refresh ещё не выполнялся. Retention/capacity checks до fence; completed-only bounded archive вместо prune; web закрыт до final four-store comparison.

### LLM backend/UI/deploy

Доработана существующая система, не второй чат: public report context, CVE/TEMP partition, whole counts/coverage, owner/session/consent/quotas/durable history, errors/cancel/retry/duplicate guards. Исправлены независимые review findings wire schema/model mismatch/readiness error redaction. Provider stream=false: NDJSON delivery завершённого ответа, **не native token streaming**.

Актуальный catalog-verified source profile: OpenRouter `xingchen-agi/xing4.0-29b-a4b:free` → `phala`, zero-price caps/ZDR/deny collection/no fallback. Старый Apodex не имел endpoints на каталоговой проверке. Catalog не заменяет настоящий browser→provider smoke; model availability перепроверять. Public backend prohibits paid/env-key fallback.

Безопасный setup вне Git: `python3 scripts/public-llm-config.py --set-key`, hidden TTY input; текущий key отсутствует. Не просить ключ в чат и не искать его в старых env/holders. File→stdin→new network-none initializer→UID65532 readonly API-only key volume имеет отдельный helper; сам provisioning ещё НЕ выполнен.

Новый deploy source: `scripts/public-llm-stand.mjs`, fixed public LLM overlay, отдельные `public-stand.nginx.conf`/Dockerfile; history ingress on, runtime off; 7 services/6 networks, optional key volume; native one-shot quota/history init; four-store backups/typed comparison; web opens last. Main/refresh сохраняют persisted descriptor. Clean stop→up source regression исправлена.

### Secrets

Свежий isolated qualification, без исторических holders/scripts: реальные Trivy вызовы с двумя искусственными canaries, native sanitized output→public adapter/consumer→temporary SQLite→owner HTTP/SSE. Исправлен exact-row dedup, ID первого исходного вхождения сохранён; path/Match/source text не хэшируются и не публикуются. Различные места/строки/rules/layers не сливаются. Derived duplicate rows маркированы как harness mutation, не настоящий duplicate output Trivy.

Последняя scoped evidence:4 native invocations по2 findings,61 named qualification checks,4 JSDOM UI tests; cleanup0containers. Это НЕ production browser E2E, cancellation controlled barriers после native output, private verifiedArchive preinvoke wrapper не квалифицирован этим proof. См. `public-secrets-qualification-20261020.dedup.*`, исходные attempts сохранены.

### Спецификации

Подготовлены full-result DOC1/2/6 reconciliation files и live-base captures; не patches. `docs/public-spec-reconciliation-20261020.md` содержит bases/hashes/deltas/preservation/source anchors. MCP full-result validation/propose/apply ещё не выполнены координатором; серверные DOC/deltas НЕ обновлены. Не применять старые mixed future targets wholesale, не подменять behaviour no-spec-impact.

## Новый HOLD: точное продолжение

Только audit **`deploy-8d83a8806715c2f0fa575efedee1b0af`**. Original entries `.operation.lock`: `helper-fenced.json`, `llm-candidate/`, `mutation.json`; `continue.json` отсутствовал на последнем checker. Original fenced core backups сохранены, candidate image pins ещё не были опубликованы на build failure.

Причина исходного build exit1 точно неизвестна: старый launcher подавил stderr/category. Нельзя объявлять COPY/TS/resources причиной без evidence. Partial build заменил worker tag и прежний worker immutable image Docker больше не inspect-ит. Старый worker НЕ сертифицирован по metadata и НЕ должен запускаться/exec.

Source-only Dockerfile closures (web TS/Vite, API/worker TS) прошли. Добавлены serial builds/substages/sanitized failure records и **узкий current-build checker/continuation**, не generic unlock. Historical source fence исходной операции не был durable: продолжение явно принимает reviewed CURRENT source, не выдуманную historical equivalence.

Независимый reviewer сначала выявил P1 token execution-dependency closure gap; исправлено AST-derived bounded transitive15first-party modules + byte/directory proofs + runtime checks до каждой boundary и сразу перед intent. Original reviewer **cleared P1, scoped source GO**,17 targeted tests independently PASS; автор full112PASS. Другой reviewer также scoped GO preservation/retire-only. Ни один reviewer continuation не выполнял.

Последний actual read-only checker token (не секрет):
`292bc2428192409dce9e80f06acb6cb3311cf4ede078da0ca3b754473330f4d3`.

Сначала ещё раз readonly:

```sh
node scripts/public-llm-stand.mjs check-current-build --audit deploy-8d83a8806715c2f0fa575efedee1b0af
```

Если source/state изменились, старый token использовать нельзя: получить fresh checker/review, не обходить fence. При неизменном reviewed состоянии следующая narrow owner-authorized операция:

```sh
node scripts/public-llm-stand.mjs continue-current-build --audit deploy-8d83a8806715c2f0fa575efedee1b0af --review 292bc2428192409dce9e80f06acb6cb3311cf4ede078da0ca3b754473330f4d3 --ack-reviewed-current-source --ack-retire-only-unavailable-worker
```

Один submission. При refusal/failure сохранить новый точный phase/HOLD, не retry/ручной unlock/исторический recovery. Mandatory network-none current-store→original-backup comparison выполняется ДО build/init/start. Original worker только retire/replace; backuphelper из inspectable original API, затем validated candidates. Original evidence не перезаписывается; web только после four-store acceptance. Source changes во время continuation запрещены.

## Конечная очередь после восстановления

1. Закончить current reviewed continuation, вернуть8081 running; native namespace/resources/ingress/readiness и preservation/accounts/reports/JWT/history/quota доказать фактически.
2. Новые disposable browser accounts только8081: registration/login/manualtarget/eligibility/checks/create/status/events/native report/counts/filters/pages/cancel/history/reload/freshlogin, ownership/error boundaries; без fabricated cookies.
3. Настоящий provider blocker: owner вводит ключ скрыто внеGit; безопасный newpublic provisioning+одна activation;2 коротких последовательных browser сообщений по своему реальному отчёту с явным consent, history reload/login, foreign denial и provider failure. Без ключа закончить всё остальное, но НЕ заявлять chat generation PASS.
4. Настоящий public LLM-enabled CVE no-op/refresh preservation/readiness и schedule install/status; не считать old8080 updater public updater. Остановленный/HOLD стенд scheduler не должен просыпать.
5. Fresh full DOC1/2/6 validation/propose/apply через MCP, task source; реальные [review]/[done]/components/strict closure только по исходным AC. Остальные задачи не закрывать каскадом.
6. README/public operator docs по фактическому результату. Разумный targeted+final API/UI/typecheck/lint/main/admin build; предыдущие1302/428PASS не новая валидация. Known SSE/UI intermittency и chunks warning не объявлены fixed.
7. Review всех новых modified/untracked файлов, secrets/private state exclusion; commit/push только проверенной работы в текущую ветку безforce/newbranch/main. Пока коммита/push этого инкремента нет.

## Parallel execution и безопасность

Использовать реальные spawn agents, минимум3 одновременно, пока есть независимые полезные задачи: lifecycle/CVE, LLM+browser, spec/security verification. Координатор единолично выполняет shared live maintenance; reviewers read-only, write scopes disjoint. Во время pinned-source continuation никто не редактирует execution/source closure. Не создавать фиктивных/пустых агентов ради счётчика; зависимые lifecycle шаги последовательны. При отсутствии spawn tool сообщить честно, не имитировать участников.

Защищены8080/dip-local-full/dip-auth-stand/.local-auth/retained preservation,key-snapshot,history-wire,old-api holders и backups/keys/HOLD. Никаких inspect privateEnv/key search/exec/cp/start/stop/rm/prune/recovery старых ресурсов. Не печатать JWT/keys/passwords/fullEnv/raw scanner/provider payloads/signedURLs. Текущие public own backups/state остаются ignored/private, в Git не добавляются. Host/runtime/LinuxEngine/publicdeployment отдельно не квалифицированы и image-only завершение не блокируют.
