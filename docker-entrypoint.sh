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
# writable data to `node`, then drops privileges for the server itself.
if [ "$(id -u)" = "0" ]; then
  node_uid="$(id -u node)"
  # Hand a tree to node, chowning ONLY the inodes not already node-owned (so a correctly-owned
  # tree costs a stat-walk, not a full re-chown, on every boot). `-h` plus find's default
  # no-follow-symlink traversal mean a compromised node cannot plant a symlink that a later root
  # chown would dereference into a protected target (e.g. the /app code tree).
  chown_tree() { find "$1" ! -uid "$node_uid" -exec chown -h node:node {} + 2>/dev/null || true; }

  # /out holds the pre-built add-on the root cp above wrote; the server never writes it, but the
  # HOST user manages ./addon, so hand it over — via chown_tree, never `chown -R`, so a symlink
  # planted here can never redirect the chown into /app.
  [ -d /out ] && chown_tree /out

  cases_root="${DFIR_CASES_ROOT:-/data/cases}"
  # Resolve to the ABSOLUTE path the server will use — it resolves a relative DFIR_CASES_ROOT
  # against this same working directory (/app/companion) — so dirname yields the real parent
  # rather than ".", and an /app-rooted misconfig is detected rather than silently skipped.
  case "$cases_root" in
    /*) abs_cases_root="$cases_root" ;;
    *) abs_cases_root="$(realpath -m "$cases_root" 2>/dev/null || echo "$(pwd)/$cases_root")" ;;
  esac
  mkdir -p "$abs_cases_root" 2>/dev/null || true
  # Always hand over the evidence/case store itself (recursively — a legacy root-written tree and
  # large evidence dirs both need it).
  chown_tree "$abs_cases_root"
  # The server also creates GLOBAL stores (logs, templates, team-auth, diagnostics, …) as
  # subdirectories of the cases root's PARENT (see runtimeStores.ts). Make that parent writable
  # so the server can create them — but NEVER recursively rewrite ownership across a shared
  # mount's unrelated files. Only /data, the image's dedicated data dir, is recursed (to migrate
  # a legacy root-owned /data on upgrade). For any other custom parent, hand over just the
  # directory entry so new stores land node-owned while its existing contents keep their owners.
  # A parent of / or /app (a root placed at the filesystem root or under the code tree) is a
  # misconfig that is refused with a warning — only the case dir chowned above is handed over.
  data_root="$(dirname "$abs_cases_root")"
  case "$data_root" in
    /data | /data/*)
      chown_tree "$data_root"
      ;;
    /|.|"")
      echo "dfir-entrypoint: DFIR_CASES_ROOT=$cases_root has no dedicated parent directory; global stores would land in '$data_root' and may be unwritable — set DFIR_CASES_ROOT to a subdirectory of a mounted volume (e.g. /data/cases)" >&2
      ;;
    /app | /app/*)
      echo "dfir-entrypoint: DFIR_CASES_ROOT=$cases_root resolves under the root-owned /app code tree ($abs_cases_root); its sibling stores (logs, templates, team-auth) will be unwritable — set DFIR_CASES_ROOT to an absolute path on a mounted volume (e.g. /data/cases)" >&2
      ;;
    *)
      # Custom data dir on a mount: hand over the directory ENTRY only (not its unrelated
      # contents) so the server can create its stores there.
      chown -h node:node "$data_root" 2>/dev/null || true
      ;;
  esac
  # Explicit out-of-tree stores, if configured, get the full (node-owned-skipping) tree.
  for store in "${DFIR_OCR_CACHE:-/data/ocr-cache}" "${DFIR_LOG_DIR:-}"; do
    [ -n "$store" ] || continue
    mkdir -p "$store" 2>/dev/null || true
    chown_tree "$store"
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
