# Public image-only: реальная попытка запуска и очистка — 2026-10-18

## Что выполнено

Docker Desktop daemon28.0.4 доступен, context `desktop-linux`, Unix endpoint `/Users/vsevolod/.docker/run/docker.sock`. Прежний `dip-local-full` автоматически поднялся при запуске Docker; его API healthy, финальный HTTP8080=200. Он не останавливался, не пересоздавался и не мигрировался этой работой. Его аккаунты/JWT/volumes сохранены. Старые dip-auth-stand, preservation/key-snapshot/history-wire holders и private Env/keys/volumes не затрагивались.

Первый real `public-image-stand up --build --isolated` отказал на Compose normalization ДО Docker mutations. После корректировки проверены реальные zero/default формы `networks.ipam={}` и `entrypoint=null`; иные IPAM/entrypoint authorities по-прежнему запрещены.

Следующая сборка создала все4 own images:

- egress `sha256:d0418470d1bcbe189f1001638b7b7da03b6b6a900a87f47ef31f07f962c212b5`
- worker `sha256:fade30895e07082997233ef0a9ef766ef41d4bac7571174d8b81488cc4893cb5`
- api `sha256:f4a47f3ecc3471def5c557e9a87dedca1fa09a220662643cf68a35791df3dc6d`
- web `sha256:12b27c26e8f77cfb0a50becf5dc4ecf6eae36d398d26cf8b8a68f48065b0148c`

Pre-start image guard выявил отличия real base metadata: Python gateway без LANG, Linux Node/Python `ArgsEscaped=true`, web WorkingDir `/`, containerd own-repository self-digests. Independent policy расширена только для этих конкретных benign форм, без hook/Env/entrypoint bypass. Ошибочные types/roles/foreign digests/extra aliases остаются отказами. Регрессии и независимый review записаны в public-image-launcher-review-20261018.md; isolated suite66/66 PASS. Финальные ESLint и git diff check PASS.

## HOLD и его честная история

Исходный build-phase HOLD не удалён вручную и не объявлен успешным запуском. После zero containers/volumes/networks census, public image verification и независимого source review выполнен explicit build-only reconciliation:

`reconciliations/build-only-06ee5ffe70385c32098d737429797a7c`

Его результат — `NOT_EXECUTED_SERVICES`, original outcome `HOLD_PRESERVED`, оригинальные bytes/identity истории сохранены. Собственный новый JWT/profile не вращались и не печатались. Read-only отказы proof до успешного reconciliation также не объявлены успешной квалификацией.

После этого actual `up --isolated` прошёл до submission сервиса, но start отказал. Сейчас новый operation HOLD/start-submission сохранён. **Не использовать build-only reconciliation для этого нового HOLD**, не удалять locks/pins вручную и не повторять up вслепую.

Финальный public namespace:
- ZERO containers, ZERO volumes;
- только2 пустые сети: `dip-public-images_registry_uplink` (172.28.0.0/16) и `dip-public-images_auth_internal` (172.29.0.0/16);
- HTTP8081 недоступен; реальных новых account/scan не создано;
- native browser/Trivy proof НЕ выполнялся и PASS не присваивался.

Наблюдаются30 bridge networks и стандартные Docker pools; исчерпание default address pool — сильная гипотеза, **не подтверждённая оригинальным stderr** (launcher безопасно скрыл Docker output). Следующий diagnostic/start должен сохранять только фиксированную безопасную категорию ошибки, не raw Env/credentials.

## Фактическая очистка

После независимого repo/provenance assessment, fresh immutableID/soleTag/all-container ancestor fences удалены exact tags без force и без parent pruning:
- `dip-final-prebuilt-gateway-72e15222635a4190:636b834`
- `dip-final-prebuilt-web-72e15222635a4190:636b834`
- `dip-final-check-worker:636b834`
- `dip-final-check-api:636b834`

Иные tags/images, containers, volumes, networks и build cache не удалялись. Физический объём освобождённого диска не измерялся. Исторические textual receipts не менялись; непосредственный prebuilt replay этих4 tags теперь недоступен — это не разрешение повторять старые proofs.

## Требуемое точное разрешение

9/9 нижеперечисленных сетей имеют `Containers={}`, но старые receipts ЯВНО сохраняли их после неудавшихся disposable CVE attempts, а последующий retirement plan сохранял ВСЕ networks. Поэтому общий cleanup-запрос не трактуется как отмена retention:

Для каждого prefix:
- `dip-cve14-proof-0a0c92726b8cd4e1`
- `dip-cve14-proof-9bef4d56d7aad6d7`
- `dip-cve14-proof-832cb6115c24c136`

сети с suffixes `_auth_internal`, `_scan_internal`, `_registry_uplink` — всего9 exact names.

Нужен explicit owner release **только этих9 пустых сетей** либо отдельно согласованный новый subnet plan. Даже после release — fresh exactID/labels/zero-endpoint checks, nonforce targeted removal, никаких prune/old holder operations. Полные IDs/provenance: docs/docker-cleanup-assessment-20261018.md.

Затем необходимо отдельно reviewed reconciliation нового start-HOLD с сохранением original evidence/own state, actual launch/postflight и `public-image-live.mjs --run-native`. Исходный8080 остаётся доступным. Full TASK2 пока blocked, новых done/parent cascade нет; progress/blocker записаны в Flownix.
