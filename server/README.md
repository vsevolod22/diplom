# Backend — fail-closed API и worker

NestJS + TypeScript: HTTP API, управление заданиями сканирования Docker-образов и контейнеров, нормализация результатов внешних сканеров, события прогресса и интеграция с LLM.

В `api/` реализованы owner-scoped scan API, cookie browser ingress, SQLite ledger с транзакционным outbox, SSE/cancel и сохранённые отчёты. `view=report-v1` добавляет глобальные фильтры и query/snapshot-bound пагинацию CVE/SBOM/Secrets, сохраняя legacy-чтение. Worker проверяет архивы и нормализует результаты Trivy; CVE допускаются только с проверенным подписанным release и явной temporal policy. См. `api/README.md` и `security-lab/README.md`.

Runtime/broker, history и LLM имеют отдельные opt-in gates и не объявляются доступными только по наличию исходников. Docker Engine не должен попадать в браузер или основной API. Общий baseline проходит локальные тесты; **текущий deployment не готов**, сохранённый стенд под HOLD. До снятия операционных блокеров не запускайте старый worker или recreate/refresh helpers поверх пользовательских volumes. Актуальная граница проверок: `../docs/release-readiness-20261015.md`.

## Локальный replacement-ключ OpenRouter

Серверный адаптер читает `OPENROUTER_API_KEY` из окружения API (`api/src/llm/openrouter-provider.ts`); наличие/работоспособность реального ключа здесь не подтверждается. Если ключ раскрыт в чате, отзовите его в OpenRouter и создайте **новый**. Не передавайте его агенту, в аргументах команд, через shell `export`, Vite-переменные, документацию, логи или трекер.

Из корня `diplom` запустите **самостоятельно в локальном интерактивном терминале**:

```sh
python3 scripts/set-openrouter-key.py
```

Утилита запросит новый ключ и подтверждение через скрытый `getpass`. Она пишет только `server/.env.openrouter.local` с правами `0600`: создаёт отсутствующий файл эксклюзивно либо заполняет только свой точный comment-only шаблон. Для предварительного создания родителем/оператором шаблон — ровно одна строка с завершающим LF:

```text
# Local OpenRouter API-only replacement key; managed by scripts/set-openrouter-key.py.
```

Не добавляйте пустое `OPENROUTER_API_KEY=` или placeholder: они перекроют прежний ключ. Существующие credentials, иной текст, нулевой файл, symlink, hardlink, небезопасные права или занятый lock вызывают отказ без вывода содержимого. Утилита не читает `.env.local`/`stand.env`, не загружает окружение приложения, не включает ИИ, не вызывает Docker/провайдера и не заменяет уже записанный ключ. Запись защищена эксклюзивным созданием/проверкой inode и advisory-lock между экземплярами утилиты; произвольные параллельные редакторы того же пользователя не поддерживаются. Не редактируйте файл одновременно; при прерванной записи не повторяйте поверх него.

Opt-in `deploy/compose.stand.openrouter.free.yaml` сохраняет обязательный `../.env.local`, затем добавляет необязательный `../.env.openrouter.local` **только для API**. Отсутствующий или comment-only файл не меняет прежнюю инъекцию ключа; заполненный добавляет только replacement `OPENROUTER_API_KEY`. Worker, `stand.env`, routing/enable/quota defaults не меняются. Нужен Docker Compose с поддержкой `env_file.required` (2.24.0+); наличие этой версии здесь не проверялось. Файл уже исключён из Git и Docker build context общими env-правилами.

Это подготовка локальной конфигурации, **не развёртывание и не активация**: отдельные approvals, согласие на отправку данных и согласованное operator-window остаются обязательными. Не используйте этот файл как Compose `--env-file`, не печатайте `docker compose config`/container env, не обходите deploy-helper проверки и не расширяйте чтение секретов ради нового необязательного файла. Обычный запуск без данного opt-in overlay его не загружает.
