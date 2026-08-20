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
  # Hand the writable data tree to node so the unprivileged server can create and UPDATE it —
  # including stores left by the older root-running image, whose bind-mount root may already be
  # host-uid-1000 while the case directories inside it are still root-owned. The global stores
  # (logs, templates, team-auth, diagnostics, …) are created as subdirectories of the cases
  # root's PARENT (see runtimeStores.ts), so that parent — not just cases/ — is the tree to
  # hand over. A cases root placed directly at a filesystem root (parent "/") is a misconfig
  # whose siblings would land in /, so warn and chown only the case root rather than recursing
  # the whole filesystem. `find` chowns just the inodes NOT already node-owned, so a
  # correctly-owned tree costs a stat-walk not a full re-chown; `-h` plus find's default
  # no-follow-symlink traversal keep a compromised node from redirecting a chown through a
  # planted symlink. (Operators with a truly enormous store can skip this by setting a compose
  # `user:` so the container never starts as root.)
  cases_root="${DFIR_CASES_ROOT:-/data/cases}"
  # Resolve to the ABSOLUTE path the server will use — it resolves a relative DFIR_CASES_ROOT
  # against this same working directory (/app/companion) — so dirname yields the real parent
  # rather than ".", and an /app-rooted misconfig is detected rather than silently skipped.
  case "$cases_root" in
    /*) abs_cases_root="$cases_root" ;;
    *) abs_cases_root="$(realpath -m "$cases_root" 2>/dev/null || echo "$(pwd)/$cases_root")" ;;
  esac
  data_root="$(dirname "$abs_cases_root")"
  case "$data_root" in
    /|.|"")
      echo "dfir-entrypoint: DFIR_CASES_ROOT=$cases_root has no dedicated parent directory; global stores would land in '$data_root' and may be unwritable — point DFIR_CASES_ROOT at a subdirectory of a mounted volume (e.g. /data/cases)" >&2
      data_root="$abs_cases_root"
      ;;
    /app | /app/*)
      # A relative or /app-rooted case root places the mutable data tree under the root-owned
      # /app code tree, which must NOT be chowned to node. Hand over only the case directory
      # itself and tell the operator to use an absolute path on a mounted volume.
      echo "dfir-entrypoint: DFIR_CASES_ROOT=$cases_root resolves under the root-owned /app code tree ($abs_cases_root); its sibling stores (logs, templates, team-auth) will be unwritable — set DFIR_CASES_ROOT to an absolute path on a mounted volume (e.g. /data/cases)" >&2
      data_root="$abs_cases_root"
      ;;
  esac
  for store in "$data_root" "${DFIR_OCR_CACHE:-/data/ocr-cache}" "${DFIR_LOG_DIR:-}"; do
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
