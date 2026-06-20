#!/bin/bash
# Runs in the background while the user reads the intro (~3 min).
set -e

cd /root

# Clone the repo (shallow — only the latest commit)
git clone --depth 1 https://github.com/hasamba/DFIR-Companion.git dfir-companion

cd dfir-companion/companion

# Install all dependencies (including dev deps needed for the TypeScript build)
npm ci 2>&1

# Compile TypeScript -> dist/
npm run build 2>&1

# Drop dev dependencies so the running process is leaner
npm prune --omit=dev 2>&1

# Start the companion server in the background.
# DFIR_HOST=0.0.0.0 lets KillerCoda's browser panel reach it.
# No demo mode — each KillerCoda session is isolated, so users have full access.
DFIR_HOST=0.0.0.0 \
DFIR_PORT=4773 \
DFIR_CASES_ROOT=/root/dfir-companion/cases \
node dist/server.js &

# Wait for the health endpoint (max ~90 s)
echo "Waiting for DFIR Companion to start..."
for i in $(seq 1 45); do
  if curl -sf http://localhost:4773/health > /dev/null 2>&1; then
    echo "DFIR Companion is ready!"
    exit 0
  fi
  sleep 2
done

echo "Server still starting — it may need another moment."
