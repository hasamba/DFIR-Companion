# syntax=docker/dockerfile:1
#
# DFIR Companion — single-image build (companion server + dashboard + browser add-on).
# Build context is the REPO ROOT: the server serves public/ from a path relative to itself
# (../../public next to companion/dist), so both companion/ and public/ must be in the image.
#
# Deliberately NO Ollama and NO LiteLLM here. For AI, point DFIR_AI_* at any OpenAI-compatible
# endpoint (a model you host, a remote provider, or an Ollama/LiteLLM you run separately).

# ---- Stage 1: build the companion server (TypeScript -> dist) + prune to prod deps ----
FROM node:22-slim AS companion-build
WORKDIR /app/companion
# Install with the lockfile first (better layer caching). npm ci inside the image fetches the
# correct linux-native binaries (e.g. sharp's libvips) — never copy host node_modules in.
COPY companion/package.json companion/package-lock.json ./
RUN npm ci
COPY companion/tsconfig.json ./
COPY companion/src ./src
RUN npm run build
# Drop dev dependencies (tsx, typescript, vitest, @types). Keeps prod deps incl. sharp.
RUN npm prune --omit=dev

# ---- Stage 2: build the browser add-on (extension) ----
FROM node:22-slim AS extension-build
RUN apt-get update \
  && apt-get install -y --no-install-recommends zip \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app/extension
COPY extension/package.json extension/package-lock.json ./
RUN npm ci
COPY extension/ ./
RUN npm run build \
  && (cd dist && zip -r ../dfir-companion-extension.zip .)

# ---- Stage 3: runtime ----
FROM node:22-slim AS runtime
LABEL org.opencontainers.image.title="DFIR Companion" \
      org.opencontainers.image.description="Post-detection DFIR analysis companion (server + dashboard + browser add-on)" \
      org.opencontainers.image.source="https://github.com/hasamba/DFIR-Companion" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

ENV NODE_ENV=production \
    DFIR_HOST=0.0.0.0 \
    DFIR_PORT=4773 \
    DFIR_CASES_ROOT=/data/cases

WORKDIR /app/companion

# Compiled server + production dependencies + package.json (for "type": "module").
COPY --from=companion-build /app/companion/dist ./dist
COPY --from=companion-build /app/companion/node_modules ./node_modules
COPY --from=companion-build /app/companion/package.json ./package.json
# Dashboard + static assets — served from ../../public relative to dist/server.js.
COPY public /app/public
# Pre-built browser add-on (the entrypoint copies it to /out so you can "Load unpacked").
COPY --from=extension-build /app/extension/dist /opt/dfir-extension/dist
COPY --from=extension-build /app/extension/dfir-companion-extension.zip /opt/dfir-extension/dfir-companion-extension.zip

COPY docker-entrypoint.sh /usr/local/bin/dfir-entrypoint
RUN chmod +x /usr/local/bin/dfir-entrypoint \
  && mkdir -p /data/cases /out

EXPOSE 4773
ENTRYPOINT ["dfir-entrypoint"]
