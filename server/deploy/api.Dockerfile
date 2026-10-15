FROM node:24.11.1-bookworm-slim
RUN corepack enable && corepack prepare pnpm@10.10.0 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY server/api/package.json server/api/package.json
RUN NODE_OPTIONS=--max-old-space-size=1024 pnpm install --frozen-lockfile --filter @diplom/scan-api... --child-concurrency=1 --network-concurrency=4
COPY server/api/src server/api/src
COPY server/runtime/src server/runtime/src
COPY server/api/tsconfig.json server/api/tsconfig.json
COPY server/deploy/trust/db-signing-key.pub.pem server/deploy/trust/db-signing-key.pub.pem
# Check shipped default/LOCAL entrypoints, not repository tests with frontend/broker imports.
RUN printf '%s\n' '{"extends":"./tsconfig.json","files":["src/main.ts","src/oci/nginx-local.main.ts","src/worker/verify-vuln-db-release.ts"],"include":[]}' > server/api/tsconfig.deploy.json \
    && NODE_OPTIONS=--max-old-space-size=1024 pnpm --filter @diplom/scan-api exec tsc --project tsconfig.deploy.json \
    && node -e "require('./server/api/node_modules/better-sqlite3')(':memory:').close()"
WORKDIR /app/server/api
USER 65532:65532
CMD ["node", "--import", "tsx", "src/main.ts"]
