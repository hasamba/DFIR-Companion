#!/bin/sh
set -e

# The browser add-on (extension) runs INSIDE your browser, not in this container. Copy the
# pre-built, unpacked add-on (and a zip) to /out so you can load it via your browser's
# Extensions page -> "Load unpacked" -> ./addon/dist on the host (mapped to /out here).
if [ -d /opt/dfir-extension ]; then
  cp -R /opt/dfir-extension/. /out/ 2>/dev/null || true
fi

# Railway (and similar PaaS) inject PORT; map it to DFIR_PORT so our server binds there.
if [ -n "$PORT" ]; then
  export DFIR_PORT="$PORT"
fi

# The companion answers only to hostnames it recognises — loopback, bare IP addresses, and whatever
# the operator configured. That is the DNS-rebinding defence (#280): a rebound name is precisely
# what must NOT be trusted, so a public hostname can never be inferred from a request header.
# Railway publishes the real one as an environment variable, set by the platform and beyond the
# reach of any request, so it is safe to trust here and saves the operator a manual step.
if [ -n "$RAILWAY_PUBLIC_DOMAIN" ]; then
  if [ -n "$DFIR_ALLOWED_ORIGINS" ]; then
    export DFIR_ALLOWED_ORIGINS="${DFIR_ALLOWED_ORIGINS},https://${RAILWAY_PUBLIC_DOMAIN}"
  else
    export DFIR_ALLOWED_ORIGINS="https://${RAILWAY_PUBLIC_DOMAIN}"
  fi
fi

# The server must not parse hostile evidence as root, but the Docker daemon auto-creates
# missing bind-mount directories root-owned — and case stores written by the older root
# image are root-owned throughout. So this entrypoint starts as root purely to hand the
# writable mounts to `node`, then drops privileges for the server itself. /out (the
# pre-built add-on just copied above) is small enough to fix up unconditionally.
if [ "$(id -u)" = "0" ]; then
  node_uid="$(id -u node)"
  chown -R node:node /out 2>/dev/null || true
  # Hand every CONFIGURED writable store to node so the unprivileged server can create and
  # UPDATE case data — including stores outside /data (a custom DFIR_CASES_ROOT bind mount)
  # and stores left by the older root-running image, whose bind-mount root may already be
  # host-uid-1000 while the case directories inside it are still root-owned. `find` walks
  # each root and chowns only the inodes NOT already owned by node, so a correctly-owned
  # tree costs a stat-walk rather than a full re-chown on every boot; `-h` plus find's
  # default no-follow-symlink traversal means a compromised node cannot redirect a chown
  # through a planted symlink. (Operators with a truly enormous store can skip this entirely
  # by setting a compose `user:` so the container never starts as root.)
  for store in "${DFIR_CASES_ROOT:-/data/cases}" "${DFIR_OCR_CACHE:-/data/ocr-cache}" "${DFIR_LOG_DIR:-}"; do
    [ -n "$store" ] || continue
    mkdir -p "$store" 2>/dev/null || true
    find "$store" ! -uid "$node_uid" -exec chown -h node:node {} + 2>/dev/null || true
  done
  # setpriv execs in place, so Node stays PID 1 and docker stop signals it directly;
  # --init-groups sheds root's supplementary groups. setpriv changes credentials but NOT
  # HOME/USER/LOGNAME, so set node's home explicitly (env, preserving DFIR_* config) —
  # otherwise `~/…` paths like DFIR_CASES_ROOT / DFIR_LOG_DIR would resolve under the
  # now-inaccessible /root.
  exec setpriv --reuid=node --regid=node --init-groups \
    env HOME=/home/node USER=node LOGNAME=node node dist/server.js
fi

# Already unprivileged (e.g. a compose `user:` override): the operator owns mount
# permissions; hand off to the Node server as PID 1 so signals stop it cleanly.
exec node dist/server.js
