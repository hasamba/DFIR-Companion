#!/bin/bash
# Runs silently in the background. All output goes to /tmp/dfir-setup.log
# so the user can watch progress with: tail -f /tmp/dfir-setup.log
exec > /tmp/dfir-setup.log 2>&1

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Cloning DFIR Companion..."
cd /root
git clone --depth 1 https://github.com/hasamba/DFIR-Companion.git dfir-companion

cd dfir-companion/companion
log "Installing dependencies (this is the slow step — 3-4 min)..."
npm ci

log "Starting server with tsx..."
DFIR_HOST=0.0.0.0 \
DFIR_PORT=4773 \
DFIR_CASES_ROOT=/root/dfir-companion/cases \
node_modules/.bin/tsx src/server.ts &

log "Server process launched (PID $!). Waiting for health endpoint..."
for i in $(seq 1 60); do
  if curl -sf http://localhost:4773/health > /dev/null 2>&1; then
    log "Server is up and healthy."
    exit 0
  fi
  sleep 3
done
log "WARNING: server did not respond after 3 min. Check for errors above."
