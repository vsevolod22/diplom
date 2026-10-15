# Docker build validation — 2026-10-15, HEAD 636b834

## Результат и границы

**API и worker: fresh `--no-cache` build PASS; deployment НЕ выполнялся.**

Проверены Dockerfiles из коммита `636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7`. Исправления `server/deploy/api.Dockerfile`, `worker.Dockerfile` и `test_dockerfile_closure.py` не понадобились. Этот документ — единственное новое versioned изменение данного build-прохода; stage/commit не выполнялись.

Это дополнение к `docs/release-readiness-20261015.md`, а не переписывание исторического результата TIMEOUT 210s. Новое разрешение пользователя: до **600s/image**, внешний timeout terminal **650000ms** на каждую сборку. API и worker собирались **последовательно**, без перекрытия тяжёлых сборок.

- Начальный HEAD подтверждён, `git status --short` был пуст.
- Процессов Docker CLI/buildctl не обнаружено; фоновые процессы Docker Desktop не объявлялись активной сборкой.
- До API история BuildKit показывала старую API-попытку `ll785mjz7qklasqozmcko29e0` как **Error, 3m30s**, не Running. Таким образом, её daemon-side завершение теперь подтверждено историей, в отличие от прежнего отчёта.
- До каждой новой сборки отдельно проверено отсутствие Running в истории default builder. После обеих сборок Running также отсутствовал. Это наблюдение default builder, не доказательство отсутствия любой посторонней нагрузки на host/Engine.
- Docker CLI `28.1.1`; Engine `28.0.4 linux/arm64`; Buildx `v0.22.0-desktop.1`; driver default/docker.
- Новый credential-free Docker config с `config.json = {}`; HOME направлен в собственный ignored work directory; окружение CLI задано allowlist, host — явно `unix:///var/run/docker.sock`. Оригинальные Docker credentials/config/context/env не читались. Public Docker Desktop buildx binary подключён symlink в собственном config.
- Контекст — `git archive` **явного allowlist путей HEAD**, не обход рабочего дерева. Private env, `.local-auth`, private keys, DB и старые mounts не читались. Единственный ключ в контексте — предусмотренный Dockerfiles **публичный** `db-signing-key.pub.pem`; его содержимое не печаталось.
- Не было Compose/start стенда, controllers, сканирования, CVE DB proof, spent incident scripts, prune, удаления/изменения существующих containers/volumes/images/tags или обращений к private registry. Добавлены только два новых image tags, их build cache и собственные одноразовые smoke containers. Это расходует общий RAM/disk/Engine; cache не очищался.
- HOLD, recovery, сохранность прежних данных, runtime topology, публичный deployment и прочие acceptance gates **не квалифицировались и не снимаются**.

## Фактические сборки

| Образ | Exit / timeout | Время CLI целиком | BuildKit ref |
|---|---|---|---|
| `dip-final-check-api:636b834` | **0 / нет** | **229.872s** | `default/default/4hz8s9l8wc5j2uw575jifdenn` |
| `dip-final-check-worker:636b834` | **0 / нет** | **173.281s** | `default/default/p50ftawxujzpqn9k8b4j8dijr` |

Оба target tags перед созданием отсутствовали; существующие tags не перезаписывались. Использованы `--load --no-cache`, но не `--pull`: свежие RUN layers, а не обещание независимой загрузки каждого base blob. Образы локальные, не push в registry. Проверена только native **linux/arm64**, не amd64 и не multi-platform runtime.

### Image IDs и export digests

`docker image inspect --format '{{.Id}}'` и Buildx `containerimage.digest` совпали. В данном containerd image store это OCI image-index digest с provenance, **не** platform config digest.

| Поле | API | Worker |
|---|---|---|
| Local image ID / index digest | `sha256:70d11c11167a1bd8ecbc68901b5cd4b99efb99a2a472c69a32d769df05673878` | `sha256:79d8cdcdf65f8d85a93390255e457f434b6cfceac6147da019fecd499d7a7844` |
| Platform manifest digest, из build log | `sha256:ac3e7f790c8b7194ad20c5d9924707d035c080e17de476e57de2e1b6e5da1239` | `sha256:245462329c995e4484114dfd75ee053153e107a12892b718d82b61fc1aabdfa3` |
| Config digest, из build log | `sha256:d6b1a03c098445e4d18a5a86cc1fffe596fca709924c5f9a04cc1be840b71c08` | `sha256:386cca946c64033bd00110c90cbe99ffbfee6e99d7162bc4e9e7be735e7beaed` |
| Image user | `65532:65532` | `65532:65532` |

Разрешённые base refs в фактических logs:

- Node: `docker.io/library/node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57`.
- Worker scanner stage: `docker.io/aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c`.

### Что действительно прошло

- `python3 -B -m unittest discover -s server/deploy -p test_dockerfile_closure.py -v`: **5/5 PASS**.
- API production TypeScript roots: `src/main.ts`, `src/oci/nginx-local.main.ts`, `src/worker/verify-vuln-db-release.ts`: **PASS в image build**.
- Worker roots: `src/worker/worker.main.ts`, `src/worker/nginx-local-worker.main.ts`, тот же verifier: **PASS в image build**.
- В обоих build RUN успешно загружен native `better-sqlite3`, открыта и закрыта только `:memory:` DB.
- Worker `trivy --version`: **0.69.3**. Команда не выполняет scan или загрузку vulnerability DB.
- Install API: `196.7s` BuildKit step; worker: `134.5s`. Обе установки закончились успешно.

Ошибок сборки и timeout в новых попытках **нет**. Не скрытые предупреждения: API один раз получил public npm `typescript-5.9.3.tgz` **ECONNRESET** с автоматическим retry; итог успешный. В обоих install logs есть Node deprecation warnings `DEP0169` (`url.parse`) и `DEP0176` (`fs.R_OK`). Это не compiler failure и не причина менять Dockerfiles в этом проходе.

## Smoke immutable images, без application boot

Два собственных контейнера запускались последовательно по **image ID**, не mutable tag. Каждый: `--rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 64 --memory 512m --memory-swap 512m --cpus 1 --user 65532:65532`; **никаких mounts, ports, env files или старых данных**. Entrypoint заменён на `/bin/sh`, приложение не импортировалось/не запускалось.

| Smoke | Exit / время | Фактический вывод |
|---|---|---|
| `dip-final-check-api-smoke-636b834` | **0 / 4.673s** | production typecheck PASS; Node `v24.11.1`; UID/GID `65532`; SQLite `3.53.2` |
| `dip-final-check-worker-smoke-636b834` | **0 / 3.600s** | то же; Trivy `0.69.3` |

TypeScript повторён с `--noEmit --incremental false` под read-only rootfs и non-root user. SQLite probe только `select sqlite_version()` в `:memory:`. После выхода exact-name `docker container ls --all` для каждого собственного контейнера вернул пустой список, exit 0: автоматическое удаление подтверждено. К существующим контейнерам lifecycle-команды не применялись.

## Безопасные команды / параметры исполнения

Все пути ниже — от корня `diplom`. Это запись использованных argv и ограничений, **не инструкция автоматически повторить сборку**: tags уже существуют и их нельзя перезаписывать. При осознанном новом прогоне нужен отдельный work directory и новые согласованные tags. Никаких `docker login`, default credential config или ambient env.

### Подготовка контекста и credential-free CLI

В выполнении directory создан отдельно, `config.json` записан как `{}` с mode 0600. Symlink указывает на установленный public plugin, а не на пользовательский Docker config. Эквивалентная последовательность подготовки и точные allowlist/CLI параметры:

```python
from pathlib import Path
import subprocess

work = Path.cwd() / 'test-results/dip-build-validation-20261015-636b834'
config = work / 'docker-config'
work.mkdir(parents=True, exist_ok=True)
config.mkdir(mode=0o700, exist_ok=False)  # не переиспользовать чужой config
(config / 'config.json').write_text('{}\n')
(config / 'config.json').chmod(0o600)
plugins = config / 'cli-plugins'
plugins.mkdir()
(plugins / 'docker-buildx').symlink_to(
    '/Applications/Docker.app/Contents/Resources/cli-plugins/docker-buildx')
env = {
    'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
    'HOME': str(work), 'DOCKER_CONFIG': str(config), 'DOCKER_BUILDKIT': '1',
}
base = ['/opt/homebrew/bin/docker', '--config', str(config),
        '--host', 'unix:///var/run/docker.sock']
paths = [
    '.dockerignore', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'package.json',
    'server/api/package.json', 'server/api/src', 'server/api/tsconfig.json',
    'server/runtime/src', 'server/deploy/trust/db-signing-key.pub.pem',
    'server/deploy/api.Dockerfile', 'server/deploy/worker.Dockerfile',
]
context = work / 'context-636b834.tar'
with context.open('xb') as output:
    subprocess.run(['git', '--no-pager', 'archive', '--format=tar', '636b834',
                    '--', *paths], stdout=output, check=True, timeout=20)
```

Контекст: **2,355,200 bytes, 261 tar entries, 0 symlinks/hardlinks**; SHA-256 `5aadba9fd28a72becec03dc5a8f4f9eb30f5f7ce97e056850ae0cfe427f7d33e`.

Read-only preflight argv, каждый под тем же `env`, timeout 20s:

```python
base + ['version', '--format', '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}']
base + ['buildx', 'version']
base + ['buildx', 'history', 'ls']
base + ['buildx', 'history', 'ls', '--format', '{{.Status}}']
base + ['image', 'inspect', '--format', '{{.Id}}', 'dip-final-check-api:636b834']
base + ['image', 'inspect', '--format', '{{.Id}}', 'dip-final-check-worker:636b834']
```

Перед каждым build проверялось: history exit 0, нет `running` (case-insensitive); target inspect — именно `No such image`, иначе STOP. Первая попытка вызвать buildx до подключения public plugin вернула CLI error 125 `unknown flag: --format`; после symlink buildx/history работают. Это tooling preflight error, **не** ошибка Dockerfile/build.

### Точные build argv и timeout wrapper

Выполнены по одному, `role='api'`, затем `role='worker'`, с terminal `timeout_ms=650000` **на каждый**, перед вторым — повторный history check. Общие значения `base`, `env`, `work`, `context` — выше.

```python
import os, signal

# role = 'api' для первой команды; role = 'worker' для второй.
tag = 'dip-final-check-' + role + ':636b834'
command = base + [
    'buildx', 'build', '--builder', 'default', '--load', '--no-cache',
    '--progress', 'plain', '--tag', tag,
    '--iidfile', str(work / (role + '.iid')),
    '--metadata-file', str(work / (role + '.metadata.json')),
    '--file', 'server/deploy/' + role + '.Dockerfile', '-',
]
with context.open('rb') as source, (work / (role + '.build.log')).open('x') as log:
    proc = subprocess.Popen(command, env=env, stdin=source, stdout=log,
                            stderr=subprocess.STDOUT, start_new_session=True)
    try:
        exit_code = proc.wait(timeout=600)
    except subprocess.TimeoutExpired:
        # В этих двух успешных прогонах ветка НЕ понадобилась.
        # Только собственная process group, не daemon/стенд.
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
        # Перед другой сборкой обязательно снова проверить daemon history.
```

После exit 0 выполнено только выборочное image inspect, без вывода Config.Env:

```python
base + ['image', 'inspect', '--format',
        '{{json .Id}} {{json .RepoTags}} {{.Os}}/{{.Architecture}} user={{.Config.User}}',
        tag]
```

### Точные smoke argv

Использован тот же credential-free CLI/env. Каждый `subprocess.run` ограничен 90s; весь smoke terminal call — 220000ms. Скрипт ниже отражает argv двух **выполненных успешных** команд; повтор не нужен.

```python
import shlex

probe = ('const Database=require("better-sqlite3"); '
         'const db=new Database(":memory:"); '
         'console.log(JSON.stringify({node:process.version,uid:process.getuid(),'
         'gid:process.getgid(),sqlite:db.prepare("select sqlite_version() AS version")'
         '.get().version})); db.close();')
images = [
    ('api', 'sha256:70d11c11167a1bd8ecbc68901b5cd4b99efb99a2a472c69a32d769df05673878'),
    ('worker', 'sha256:79d8cdcdf65f8d85a93390255e457f434b6cfceac6147da019fecd499d7a7844'),
]
for role, image in images:
    body = ('node --max-old-space-size=384 node_modules/typescript/bin/tsc '
            '--project tsconfig.deploy.json --noEmit --incremental false '
            '&& printf "production typecheck PASS\\n" && node -e '
            + shlex.quote(probe))
    if role == 'worker':
        body += ' && trivy --version'
    name = 'dip-final-check-' + role + '-smoke-636b834'
    command = base + [
        'run', '--rm', '--pull', 'never', '--name', name,
        '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges:true', '--pids-limit', '64',
        '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
        '--user', '65532:65532', '--entrypoint', '/bin/sh', image, '-c', body,
    ]
    result = subprocess.run(command, env=env, capture_output=True,
                            text=True, timeout=90)
```

Последующие read-only проверки: `base + ['buildx','history','ls','--format','{{.Status}}']` и для каждого собственного имени `base + ['container','ls','--all','--filter','name=^/' + name + '$','--format','{{.ID}}']`, timeout 20s.

## Локальные evidence files

Логи, argv/exit/duration JSON, Buildx metadata, iid и smoke JSON сохранены в ignored `test-results/dip-build-validation-20261015-636b834/`. Это локальные результаты, **не** tracker artifacts, не evidence seal и не гарантия их долговечного хранения. В private registry ничего не отправлялось.

SHA-256 исходных build logs:

```text
fdf36864be6cbdc7df0f8404a5a52ad69cfd04aa58beba553e1623d7b6ceed97  api.build.log
96ebfe7f4038b0a9c49266dfea363a7f37f5bf28e13c53e65d2e95dbfce51f97  worker.build.log
```

**Итог:** прежний build-only blocker теперь проверен успешными полными ARM64 API/worker сборками и узкими immutable-image smoke checks. Это не подмена rollout/recovery/production acceptance и не основание запускать сохранённый стенд.
