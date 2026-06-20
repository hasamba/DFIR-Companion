#!/bin/bash
# Runs silently in the background. All output goes to /tmp/dfir-setup.log
# so the user can watch progress with: tail -f /tmp/dfir-setup.log
exec > /tmp/dfir-setup.log 2>&1

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Pulling DFIR Companion image (~400 MB, ~1 min)..."
docker pull ghcr.io/hasamba/dfir-companion:latest

log "Starting server..."
docker run -d \
  --name dfir \
  -p 4773:4773 \
  -e DFIR_HOST=0.0.0.0 \
  ghcr.io/hasamba/dfir-companion:latest

log "Waiting for health endpoint..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:4773/health > /dev/null 2>&1; then
    log "Server is up and healthy."
    exit 0
  fi
  sleep 3
done
log "WARNING: server did not respond after 90 s. Check container logs: docker logs dfir"
