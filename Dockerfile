# syntax=docker/dockerfile:1
#
# DFIR Companion — single-image build (companion server + dashboard + browser add-on).
# Build context is the REPO ROOT: the server serves public/ from a path relative to itself
# (../../public next to companion/dist), so both companion/ and public/ must be in the image.
#
# Deliberately NO Ollama and NO LiteLLM here. For AI, point DFIR_AI_* at any OpenAI-compatible
# endpoint (a model you host, a remote provider, or an Ollama/LiteLLM you run separately).

# ---- Stage 1: build the companion server (TypeScript -> dist) + prune to prod deps ----
# All three stages build from the same digest-pinned base (node:22-slim = Node 22.23.2 on Debian
# bookworm at the time of pinning) so builds are reproducible and a re-tagged or compromised
# upstream tag cannot slip in silently. Refresh the digest deliberately when bumping Node.
FROM node:22-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS companion-build
WORKDIR /app/companion
# Install with the lockfile first (better layer caching). npm ci inside the image fetches the
# correct linux-native binaries (e.g. sharp's libvips) — never copy host node_modules in.
COPY companion/package.json companion/package-lock.json ./
# Playwright is a devDependency and its browsers (~150MB+) are never needed in an image — the
# runtime stage below copies only dist/, the pruned node_modules, public/ and data/. Without this,
# `npm ci` here may fetch browsers that are then thrown away, slowing every build for nothing.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN npm ci
COPY companion/tsconfig.json ./
COPY companion/src ./src
RUN npm run build
# Drop dev dependencies (tsx, typescript, vitest, @types). Keeps prod deps incl. sharp.
RUN npm prune --omit=dev

# ---- Stage 2: build the browser add-on (extension) ----
FROM node:22-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS extension-build
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
FROM node:22-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS runtime
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
# Bundled offline datasets (MITRE ATT&CK groups, country centroids, D3FEND map, default tagger
# ruleset) — resolved via ../../data relative to dist/analysis/*.js, i.e. /app/companion/data.
COPY companion/data ./data
# Pre-built browser add-on (the entrypoint copies it to /out so you can "Load unpacked").
COPY --from=extension-build /app/extension/dist /opt/dfir-extension/dist
COPY --from=extension-build /app/extension/dfir-companion-extension.zip /opt/dfir-extension/dfir-companion-extension.zip

COPY docker-entrypoint.sh /usr/local/bin/dfir-entrypoint
# The server parses hostile forensic evidence, so it must not run as root — but bind mounts
# the Docker daemon auto-creates on the host arrive root-owned, so a bare USER directive would
# leave a clean-checkout `docker compose up` unable to write case data at all. Instead the
# entrypoint STARTS as root, hands the writable mounts to `node` once, and drops privileges
# with setpriv before exec'ing the server (see docker-entrypoint.sh). /app stays root-owned
# on purpose: a compromised server must not be able to rewrite its own code.
RUN chmod +x /usr/local/bin/dfir-entrypoint \
  && mkdir -p /data/cases /data/ocr-cache /out \
  && chown -R node:node /data /out
# tesseract.js would otherwise cache its OCR language model into the root-owned working
# directory; point it at a node-writable location instead (ocrRedact.ts honors this).
ENV DFIR_OCR_CACHE=/data/ocr-cache

EXPOSE 4773
# Bake liveness into the image so plain `docker run` / Portainer / Watchtower users get health
# status too, not just compose users. PORT is consulted before DFIR_PORT because the entrypoint's
# PORT->DFIR_PORT remap is an export inside the entrypoint's own process — healthcheck processes
# start from the container's configured environment and never see it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||process.env.DFIR_PORT||4773)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["dfir-entrypoint"]
