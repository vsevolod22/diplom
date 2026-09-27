FROM node:24.11.1-bookworm-slim
RUN corepack enable && corepack prepare pnpm@10.10.0 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY server/api/package.json server/api/package.json
RUN pnpm install --frozen-lockfile --filter @diplom/scan-api...
COPY server/api/src server/api/src
COPY server/api/tsconfig.json server/api/tsconfig.json
RUN pnpm --filter @diplom/scan-api typecheck && node -e "require('./server/api/node_modules/better-sqlite3')(':memory:').close()"
WORKDIR /app/server/api
USER 65532:65532
CMD ["node", "--import", "tsx", "src/main.ts"]
