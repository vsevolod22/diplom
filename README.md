# Диплом

Новый проект с каркасом React + TypeScript + Vite на основе архитектуры `autobrief`, без его бизнес-логики и секретов.

```bash
pnpm install --frozen-lockfile
pnpm dev
```

`pnpm build` собирает клиентскую и административную страницы; `pnpm dev:admin` запускает отдельный режим сборки админки. Проверки: `pnpm typecheck`, `pnpm lint`, `pnpm test`.

Описание слоёв и каталогов: [docs/architecture/README.md](docs/architecture/README.md). Предметные требования к дипломному проекту пока не заданы.
