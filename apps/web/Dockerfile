FROM node:22-alpine AS build

WORKDIR /app

# npm registry used by npm and pnpm. Override it with an npm-compatible mirror
# when registry.npmjs.org is slow or unreachable (NPM_REGISTRY in .env). The
# lockfile pins integrity hashes, so a mirror cannot substitute packages.
ARG NPM_REGISTRY=https://registry.npmjs.org/

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Install exactly the pnpm version pinned in package.json ("packageManager").
# Without a pin, corepack fetches the newest pnpm, whose stricter defaults
# (for example strictDepBuilds since v11) can reject this lockfile.
RUN npm install -g \
      --registry="$NPM_REGISTRY" \
      --fetch-retries=5 \
      --fetch-retry-maxtimeout=120000 \
      "$(node -p 'require("./package.json").packageManager')" \
 && pnpm --version

# The pnpm store lives in a BuildKit cache mount: packages fetched before a
# network failure are reused by the next build instead of downloaded again.
# Longer timeouts, more retries, and lower concurrency tolerate flaky links.
RUN --mount=type=cache,id=sleep-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile \
      --store-dir=/pnpm/store \
      --registry="$NPM_REGISTRY" \
      --fetch-retries=5 \
      --fetch-retry-mintimeout=10000 \
      --fetch-retry-maxtimeout=120000 \
      --fetch-timeout=120000 \
      --network-concurrency=8

COPY . .
RUN pnpm build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1/healthz || exit 1
