#!/bin/bash
# Runs silently in the background. All output goes to /tmp/dfir-setup.log
# so the user can watch progress with: tail -f /tmp/dfir-setup.log
exec > /tmp/dfir-setup.log 2>&1

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Installing Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>&1
apt-get install -y nodejs 2>&1
log "Node $(node --version) / npm $(npm --version) installed."

log "Cloning DFIR Companion..."
cd /root
git clone --depth 1 https://github.com/hasamba/DFIR-Companion.git dfir-companion

cd dfir-companion/companion
log "Installing dependencies (3-4 min)..."
npm ci

log "Starting server with tsx..."
DFIR_HOST=0.0.0.0 \
DFIR_PORT=4773 \
DFIR_CASES_ROOT=/root/dfir-companion/cases \
node_modules/.bin/tsx src/server.ts &

log "Server process launched (PID $!). Waiting for health endpoint..."
for i in $(seq 1 80); do
  if curl -sf http://localhost:4773/health > /dev/null 2>&1; then
    log "Server is up and healthy."
    exit 0
  fi
  sleep 3
done
log "WARNING: server did not respond after 4 min. Check for errors above."
