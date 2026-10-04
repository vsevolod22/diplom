# Локальная аттестация Trivy vulnerability DB

Это **подпись локального оператора**, НЕ подпись Aqua Security. Публичный Ed25519-ключ `db-signing-key.pub.pem` закреплён в репозитории; SHA-256 его DER/SPKI: `d75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078`. Закрытый ключ локального стенда — `.local-auth/trust/db-signing-key.pem` (0600, игнорируется Git). Перенесите резервную копию ключа в защищённое хранилище оператора; потеря ключа означает ротацию публичного ключа по отдельному ревью, утечка — отзыв и перевыпуск DB release. **Не** передавать закрытый ключ контейнерам, worker, скачивающему процессу, CI или Git.

Существующий локальный ключ создан на этой же машине *после* первоначальной HTTPS-загрузки DB. Подпись фиксирует именно принятое нами содержимое, но не является независимым доказательством издателя/истории первой загрузки. Издательская подпись не заявляется.

## Ручной выпуск (отдельно от downloader и сети worker)

1. Оператор отдельно проверяет официальный источник `ghcr.io/aquasecurity/trivy-db`, фиксирует OCI manifest digest, SHA-256 `bundle.bin` и `db/trivy.db` в своей записи о выпуске. Загрузка из registry — только по HTTPS с проверкой TLS, без отключения проверки сертификата, без непроверенного fallback/mirror и без нового egress у worker. `:2` — указатель на текущую версию, **не** закреплённый источник. Каждый новый выпуск — отдельный каталог, содержащий только `bundle.bin`, `db/trivy.db`, `db/metadata.json`; нельзя перезаписывать уже подписанный выпуск.
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

Опциональный override указывает на единственный локальный versioned release `.local-auth/trivy-db-releases/68d30a47` и **точные** digest OCI manifest и SHA-256 bundle; он не предназначен для другого окружения. API перед постановкой задания, а worker перед каждым CVE-этапом заново проверяют pinned public key, подпись, хеши и сроки; DB и release смонтированы read-only, scratch выделен в отдельный tmpfs пользователя 65532. Следующий выпуск публиковать в **новую** директорию; никогда не обновлять смонтированный release на месте. Перед каждым запуском проверить свежесть; у текущего выпуска `NextUpdate=2026-10-05T01:47:20Z`, после этого CVE должен отказывать, а не показывать «0». Заменить в override путь и оба pin только после HTTPS-получения, независимой проверки ожидаемых digest и новой подписи операторским ключом, затем повторить реальные проверки. Автоматического обновления и атомарного publisher пока нет; защищённость от изменения файлов на машине хоста между проверкой и чтением Trivy не доказана.

Подтверждённый локальный E2E: отдельный CVE и совмещённый Secrets+SBOM+CVE на pinned `library/alpine`/`linux/amd64`; 16 APK, 0 CVE в этой DB для этого образа — это **только** проверенная область образа, не гарантия безопасности. Синтетический офлайн fixture даёт OS и Node CVE, но ещё не подтверждает полный позитивный HTTP-путь для Node/OS уязвимого remote image. Работающий контейнер и ОС хоста не поддерживаются этим worker: нельзя принимать `scope=host` или использовать Docker socket/host filesystem mount в worker. Для них требуются отдельные авторизация, snapshot/provenance и границы доступа (см. `DIP-TASK-5`, `DIP-TASK-8`). TLS + собственная подпись защищают локальную цепочку после решения оператора, но не удостоверяют автора исходного OCI-артефакта.
