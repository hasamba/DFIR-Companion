#!/bin/bash
# Runs silently in the background. All output goes to /tmp/dfir-setup.log
# so the user can watch progress with: tail -f /tmp/dfir-setup.log
exec > /tmp/dfir-setup.log 2>&1

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Pulling DFIR Companion image (~400 MB, ~1 min)..."
docker pull ghcr.io/hasamba/dfir-companion:latest

# Killercoda proxies port 4773 through a hostname minted per session, not localhost, and the
# companion refuses hostnames it does not recognise (the DNS-rebinding defence, #280). Killercoda
# publishes this VM's real public URL in /etc/killercoda/host with PORT as a placeholder — see the
# platform's own network-traffic example — so the exact origin can be read at runtime rather than
# guessed from a domain suffix.
KC_ORIGIN=$(sed 's/PORT/4773/g' /etc/killercoda/host 2>/dev/null | tr -d '[:space:]')
if [ -n "$KC_ORIGIN" ]; then
  log "Killercoda public origin: $KC_ORIGIN"
else
  log "WARNING: /etc/killercoda/host not found — the dashboard may 403 when opened through the"
  log "         Traffic/Ports proxy. curl from this terminal is unaffected."
fi

log "Starting server..."
# Passed as BOTH an origin and a host: /etc/killercoda/host is documented only by example, so this
# works whether it yields a full URL or a bare hostname. Empty values parse to an empty list.
docker run -d \
  --name dfir \
  -p 4773:4773 \
  -e DFIR_HOST=0.0.0.0 \
  -e DFIR_ALLOWED_ORIGINS="$KC_ORIGIN" \
  -e DFIR_ALLOWED_HOSTS="$KC_ORIGIN" \
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
