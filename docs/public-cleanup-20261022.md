# Public8081: согласованная очистка после READY — 22.10.2026

## Scope и фактический результат

Владелец разрешил очистить Docker build cache и устаревшие images/containers **только `dip-public-images`**, сохранив последний настраиваемый/рабочий стенд. 8080, другие проекты, volumes, базы, keys, backups и исторические operation evidence исключены.

- Первый `docker --context desktop-linux builder prune --all --force` освободил **17.83 GB** build cache; это отдельное разрешение владельца на общий кэш сборок, не удаление контейнеров/образов других проектов.
- После восстановления выполнена финальная очистка build cache. `docker system df`: **Build Cache 0 / 0B**. На host примерно **23 GiB available**, вместо прежних 3.65 GiB.
- Массовое удаление project containers/images не выполнялось: команда была отменена до исполнения; текущий стенд сохранён.
- Старые public API/worker/web заменены guarded deployment; obsolete initializer helpers удалены точечно внутри preservation workflow, без повторного start/exec и без force removal. Архивы intents/checkpoints/backups сохранены.
- После READY инвентаризация нашла ровно **пять own-labelled application/gateway images**; все пять входят в текущие immutable pins. **Дополнительных устаревших own-public images, допускающих удаление, — 0.** Shared BusyBox и образы других проектов не трогались.
- Осталось ровно **семь сервисных контейнеров** public-стенда. Пять running; два volume initializer exited0 — это нормальная часть текущего descriptor, не мусор. Дополнительных старых public containers нет.

## Проверка image scope

Для каждого image проверены обе ownership labels (`org.diplom.public-image-stand=v1`, `org.diplom.public-image-project=dip-public-images`), current pins, RepoTags и image references **всех** контейнеров, включая stopped/created. Никакие Env или payload не выводились. Исторические image references сами по себе не требовали сохранения obsolete image после явного разрешения владельца; сами history records не удалялись.

Сохранены текущие application images:

| Role | Immutable image ID |
| --- | --- |
| API | `sha256:baaa16f620fde9e0ef090641b6f0418289188e637b3ccfbcb173ffef3e2e7512` |
| Worker | `sha256:7ef6b061848a5f24343fe627389ecdcc9794e0a7e7e264350c5bd7e7be35cc4a` |
| Web | `sha256:1f53451df413f13e3ca0b2df38b1bd90ce9066c69b594843d07239c1b4205fcd` |
| Registry egress | `sha256:ce9ff52cb3aa1c5f6011bec9c239c6446a1c385f30256a9cc85fc00f436c889f` |
| LLM egress | `sha256:2c34dba54c7572b5254478b7c9de8352c79f73324f2a0f8fd094079adca65f5f` |

После очистки **8081 HTTP200, 8080 HTTP200**. [Runtime recovery](public-recovery-ready-20261022.md), [actual browser scan и unresolved smoke guard](public8081launch-20261022.attempt2.md).
