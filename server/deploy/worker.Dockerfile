FROM aquasec/trivy:0.69.3 AS scanner
FROM node:24.11.1-bookworm-slim
# Trivy is a Go binary and requires the OS trust store for registry TLS.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN corepack enable && corepack prepare pnpm@10.10.0 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY server/api/package.json server/api/package.json
RUN pnpm install --frozen-lockfile --filter @diplom/scan-api...
COPY server/api/src server/api/src
COPY server/api/tsconfig.json server/api/tsconfig.json
COPY server/deploy/trust/db-signing-key.pub.pem server/deploy/trust/db-signing-key.pub.pem
COPY --from=scanner /usr/local/bin/trivy /usr/local/bin/trivy
RUN pnpm --filter @diplom/scan-api typecheck && node -e "require('./server/api/node_modules/better-sqlite3')(':memory:').close()" && trivy --version
WORKDIR /app/server/api
USER 65532:65532
CMD ["node", "--import", "tsx", "src/worker/worker.main.ts"]
