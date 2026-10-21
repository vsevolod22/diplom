FROM node:24.11.1-bookworm-slim AS build
RUN corepack enable && corepack prepare pnpm@10.10.0 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY server/api/package.json server/api/package.json
RUN pnpm install --frozen-lockfile --filter diplom...
# Explicit source closure: never copy repository state, env, scripts or test fixtures.
COPY index.html admin.html vite.config.ts tsconfig.json ./
COPY src ./src
COPY public ./public
COPY server/runtime/src/contract.ts server/runtime/src/runtime-json.ts ./server/runtime/src/
RUN node -e "require('node:fs').writeFileSync('tsconfig.public.json',JSON.stringify({extends:'./tsconfig.json',include:['src','vite.config.ts']}))" \
    && pnpm exec tsc --project tsconfig.public.json \
    && pnpm exec vite build

FROM nginx:1.27.5-alpine
COPY server/deploy/public-stand.nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8080
