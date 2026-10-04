FROM node:24.11.1-bookworm-slim AS build
RUN corepack enable && corepack prepare pnpm@10.10.0 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY server/api/package.json server/api/package.json
RUN pnpm install --frozen-lockfile --filter diplom...
COPY . .
RUN pnpm build

FROM nginx:1.27.5-alpine
COPY server/deploy/stand.nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8080
