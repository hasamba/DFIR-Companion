#!/bin/bash
# Runs silently in the background while foreground.sh shows the user a progress indicator.
set -e

cd /root

# Clone the repo (shallow — only the latest commit)
git clone --depth 1 https://github.com/hasamba/DFIR-Companion.git dfir-companion

cd dfir-companion/companion

# Install all dependencies (dev deps included — tsx is needed to run TypeScript directly)
npm ci --silent

# Start the server using tsx (no separate build step → ~2 min faster than tsc + node).
# tsx JIT-compiles TypeScript on start; import.meta.url resolves correctly from src/.
DFIR_HOST=0.0.0.0 \
DFIR_PORT=4773 \
DFIR_CASES_ROOT=/root/dfir-companion/cases \
node_modules/.bin/tsx src/server.ts &
