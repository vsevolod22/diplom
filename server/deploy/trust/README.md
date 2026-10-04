# Локальная аттестация Trivy vulnerability DB

Это **подпись локального оператора**, НЕ подпись Aqua Security. Публичный Ed25519-ключ `db-signing-key.pub.pem` закреплён в репозитории; SHA-256 его DER/SPKI: `d75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078`. Закрытый ключ локального стенда — `.local-auth/trust/db-signing-key.pem` (0600, игнорируется Git). Перенесите резервную копию ключа в защищённое хранилище оператора; потеря ключа означает ротацию публичного ключа по отдельному ревью, утечка — отзыв и перевыпуск DB release. **Не** передавать закрытый ключ контейнерам, worker, скачивающему процессу, CI или Git.

Существующий локальный ключ создан на этой же машине *после* первоначальной HTTPS-загрузки DB. Подпись фиксирует именно принятое нами содержимое, но не является независимым доказательством издателя/истории первой загрузки. Издательская подпись не заявляется.

## Ручной выпуск (отдельно от downloader и сети worker)

1. Оператор отдельно проверяет официальный источник `ghcr.io/aquasecurity/trivy-db`, фиксирует OCI manifest digest, digest слоя, SHA-256 локального `bundle.bin` и `db/trivy.db` в своей записи о выпуске. `:2` — изменяемый указатель **только для обнаружения** обновления. Ограниченный downloader работает **вне** `scan_internal` по HTTPS с обычной проверкой TLS, точным OCI digest и allowlist blob CDN; ключ подписи ему недоступен. Он не добавляет никаких hosts в egress worker и не включает новый выпуск автоматически:

   ```sh
   node server/deploy/trust/fetch-db-layer.mjs discover
   node server/deploy/trust/fetch-db-layer.mjs stage-latest /absolute/.local-auth/trivy-db-candidates
   # После независимой проверки manifest и layer digest из кандидата:
   python3 server/deploy/trust/prepare-db-release.py /absolute/candidate /absolute/new-release sha256:<reviewed-manifest> sha256:<reviewed-layer>
   ```

   `stage-latest` можно вызывать планировщиком каждые 6 часов (например, `0 */6 * * *`, с абсолютными путями к Node, скрипту и приватной директории кандидатов): он только готовит **неподписанного** кандидата. Планировщик на этой машине не установлен — команда доступна для явной настройки оператором; не добавляйте signing key в его окружение. Конвертер отвергает посторонние tar members, пути, links и превышение лимитов, записывает DB и gzip ровно этой DB (OCI слой сам является *gzip от tar*, а не локальным `bundle.bin`) и выставляет реальное `DownloadedAt`. Новый выпуск — отдельный каталог только с `bundle.bin`, `db/trivy.db`, `db/metadata.json`; изменять подписанный выпуск запрещено. Автоматически доверять новому содержимому `:2` или подписывать его ключом downloader нельзя: наша подпись не подтверждает Aqua Security.
2. На машине оператора выполнить (параметры берутся **из проверенной записи**, не из descriptor):

   ```sh
   node server/deploy/trust/sign-offline-db.mjs /absolute/release-directory .local-auth/trust/db-signing-key.pem server/deploy/trust/db-signing-key.pub.pem sha256:<reviewed-oci-manifest> <reviewed-bundle-sha256> <reviewed-db-sha256>
   ```

   Подписант требует закрытый ключ 0600, сверяет его с закреплённым открытым, hash сжатого и распакованного файлов и что gzip распаковывается точно в эту DB, проверяет schema 2 и сроки `UpdatedAt`/`DownloadedAt`/`NextUpdate`, подписывает канонический `descriptor.json` в `descriptor.sig`. Повторная подпись в том же каталоге запрещена. Ключ не используется downloader'ом.
3. Перед каждым использованием проверить **закреплённым ключом** и independently pinned hash:

   ```sh
   pnpm --filter @diplom/scan-api exec tsx src/worker/verify-vuln-db-release.ts /absolute/release-directory sha256:<reviewed-oci-manifest> <reviewed-bundle-sha256>
   ```

   При истёкшем `NextUpdate`, слишком старом `UpdatedAt`/`DownloadedAt`, подмене DB/metadata или чужой подписи — отказ, а не «0 CVE». Возврат `envelope-preflight-only` **не является** доказательством пригодности DB для сканера: отдельно запускать `server/deploy/proof/offline_vuln_db_proof.py` на настоящем Trivy 0.69.3 с теми же ожидаемыми хешами.

Подпись в рабочем каталоге сериализуется `.signing.lock`, но пара `descriptor.json`/`descriptor.sig` не публикуется атомарно: crash оставит неполный выпуск и lock до ручной проверки. Не удаляйте lock без расследования; полная атомарная публикация read-only каталога — следующий этап. Проверка сама по себе не замораживает файлы после хеширования: в будущей цепочке потребитель обязан проверять неизменяемый снимок при использовании.

Локальный стенд включает CVE **только** с дополнительным `server/deploy/compose.stand.vuln.local.yaml` поверх `compose.stand.yaml` и сохранённым `.local-auth/stand.env` (не запускать `stand:auth` поверх существующих томов: сменится JWT secret):

```sh
docker compose --env-file .local-auth/stand.env -f server/deploy/compose.stand.yaml -f server/deploy/compose.stand.vuln.local.yaml up -d --build api worker web
```

Опциональный override берёт три **операторских** pin из игнорируемого `.local-auth/stand.env`: `SCAN_VULN_RELEASE_HOST_DIR` (абсолютный путь к новому проверенному release), `SCAN_VULN_MANIFEST_DIGEST` и `SCAN_VULN_ARTIFACT_SHA256`. Существующий `SCAN_JWT_SECRET` в этом файле **сохранять**: пересоздание через `stand:auth` поверх volumes сбрасывает авторизованные сессии. После подписи и проверок сделать каталог/подкаталоги доступными на чтение и исполнение UID 65532 (`chmod 0555`), файлы — только на чтение (`chmod 0444`); закрытый ключ остаётся 0600 ВНЕ release. Заменить три pin в private env одним шагом, проверить `docker compose ... config --quiet` и пересоздать только `api worker` с обоими Compose-файлами, затем повторить authenticated CVE E2E. Не изменять release, на который ещё ссылаются контейнеры; предыдущий хранить до доказанной успешной ротации.

Текущий выпуск стенда: OCI `sha256:23b403a78807d762f6ecf1b85f526c1681a075020549ad78e4a604f84a87e02b`, `NextUpdate=2026-10-05T08:52:32Z`. API перед постановкой задания, а worker перед CVE-этапом заново проверяют закреплённый ключ, подпись, хеши и сроки; DB и release read-only, scratch — отдельный tmpfs UID 65532. После истечения срока CVE обязан отказывать, а не показывать «0». **Автоматическая подготовка кандидата есть, автоматической подписи, переключения и гарантированного бесперебойного обновления пока НЕТ**; файл на машине хоста может быть изменён привилегированным процессом даже при read-only bind. Без независимой подписи издателя нельзя выдавать unattended TLS download + подпись нашим же ключом за проверку provenance.

Подтверждённый локальный E2E: отдельный CVE и совмещённый Secrets+SBOM+CVE на pinned `library/alpine`/`linux/amd64`; современный Alpine с 16 APK дал 0 CVE, старый pinned Alpine 3.16 дал 4 CVE и после замены DB — тоже 4. Это **только** находки в конкретном образе и сроке DB, не размер общей базы и не гарантия безопасности. Синтетический офлайн fixture даёт OS и Node CVE, но ещё не подтверждает полный позитивный HTTP-путь для Node/OS уязвимого remote image. Работающий контейнер и ОС хоста не поддерживаются этим worker: нельзя принимать `scope=host` или использовать Docker socket/host filesystem mount в worker. Для них требуются отдельные авторизация, snapshot/provenance и границы доступа (см. `DIP-TASK-5`, `DIP-TASK-8`). TLS + собственная подпись защищают локальную цепочку после решения оператора, но не удостоверяют автора исходного OCI-артефакта.
