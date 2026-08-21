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
  node_home=/home/node

  # Hand a tree to node, chowning ONLY the inodes not already node-owned (so a correctly-owned
  # tree costs a stat-walk, not a full re-chown, on every boot). `-h` plus find's default
  # no-follow-symlink traversal mean a compromised node cannot plant a symlink that a later root
  # chown would dereference into a protected target (e.g. the /app code tree).
  chown_tree() { find "$1" ! -uid "$node_uid" -exec chown -h node:node {} + 2>/dev/null || true; }
  # Expand a leading ~ to node's POST-DROP home, matching the server's expandHome(), so the
  # entrypoint hands over the same path the server will use; then resolve a relative path against
  # /app/companion (the working directory the server anchors relative roots to).
  abspath() {
    case "$1" in
      "~") printf '%s' "$node_home" ;;
      "~/"*) printf '%s/%s' "$node_home" "${1#\~/}" ;;
      /*) printf '%s' "$1" ;;
      *) realpath -m "$1" 2>/dev/null || printf '%s/%s' "$(pwd)" "$1" ;;
    esac
  }

  # /out holds the pre-built add-on the root cp above wrote; the server never writes it, but the
  # HOST user manages ./addon, so hand it over — via chown_tree, never `chown -R`, so a symlink
  # planted here can never redirect the chown into /app.
  if [ -d /out ]; then chown_tree /out; fi

  cases_root="$(abspath "${DFIR_CASES_ROOT:-/data/cases}")"
  mkdir -p "$cases_root" 2>/dev/null || true
  # Always hand over the evidence/case store itself (recursively — a legacy root-written tree and
  # large evidence dirs both need it).
  chown_tree "$cases_root"
  # The server also creates GLOBAL stores as subdirectories of the cases root's PARENT (see
  # runtimeStores.ts / authFactory.ts). Make that parent usable — but NEVER recursively rewrite
  # ownership across a shared mount's UNRELATED files. Only /data, the image's dedicated data
  # dir, is recursed wholesale (to migrate a legacy root-owned /data on upgrade). For any other
  # custom parent, hand over the directory entry (so new stores land node-owned) plus only the
  # KNOWN application store subdirectories and any .dfir-auth-* the prior root image left. A
  # parent of / or /app is a misconfig, refused with a warning.
  data_root="$(dirname "$cases_root")"
  case "$data_root" in
    /data | /data/*)
      chown_tree "$data_root"
      ;;
    /|.|"")
      echo "dfir-entrypoint: DFIR_CASES_ROOT=${DFIR_CASES_ROOT:-/data/cases} has no dedicated parent directory; global stores would land in '$data_root' and may be unwritable — set DFIR_CASES_ROOT to a subdirectory of a mounted volume (e.g. /data/cases)" >&2
      ;;
    /app | /app/*)
      echo "dfir-entrypoint: DFIR_CASES_ROOT=${DFIR_CASES_ROOT:-/data/cases} resolves under the root-owned /app code tree ($cases_root); its sibling stores (logs, templates, team-auth) will be unwritable — set DFIR_CASES_ROOT to an absolute path on a mounted volume (e.g. /data/cases)" >&2
      ;;
    *)
      chown -h node:node "$data_root" 2>/dev/null || true
      for name in bundles dashboard-views diagnostics importers incident-types kev logs \
        notifications nsrl report-templates tagger templates tools updates velociraptor whitelist; do
        if [ -e "$data_root/$name" ]; then chown_tree "$data_root/$name"; fi
      done
      for auth in "$data_root"/.dfir-auth-*; do
        if [ -e "$auth" ]; then chown_tree "$auth"; fi
      done
      ;;
  esac

  # Team-auth data dir, when relocated to its own (possibly dedicated, possibly root-owned) mount:
  # authFactory uses it absolute-as-is or relative to the cases parent (no ~ expansion), and it is
  # app-dedicated, so recurse it.
  if [ -n "${DFIR_AUTH_DATA_DIR:-}" ]; then
    case "$DFIR_AUTH_DATA_DIR" in
      /*) auth_dir="$DFIR_AUTH_DATA_DIR" ;;
      *) auth_dir="$data_root/$DFIR_AUTH_DATA_DIR" ;;
    esac
    mkdir -p "$auth_dir" 2>/dev/null || true
    chown_tree "$auth_dir"
  fi

  # OCR cache (app-dedicated; default /data/ocr-cache is already covered by /data above): recurse.
  # No ~ expansion — ocrRedact.ts reads DFIR_OCR_CACHE raw, so the server would not expand it either.
  ocr_cache="${DFIR_OCR_CACHE:-/data/ocr-cache}"
  case "$ocr_cache" in /*) : ;; *) ocr_cache="$(realpath -m "$ocr_cache" 2>/dev/null || echo "$(pwd)/$ocr_cache")" ;; esac
  mkdir -p "$ocr_cache" 2>/dev/null || true
  chown_tree "$ocr_cache"

  # An explicit DFIR_LOG_DIR may point at a SHARED host log directory: the logger only needs to
  # CREATE its session file there, so hand over the directory entry only — never its (possibly
  # unrelated) contents. (Unset → logs/ beside the cases root, already handed over above.)
  if [ -n "${DFIR_LOG_DIR:-}" ]; then
    log_dir="$(abspath "$DFIR_LOG_DIR")"
    mkdir -p "$log_dir" 2>/dev/null || true
    chown -h node:node "$log_dir" 2>/dev/null || true
  fi
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
