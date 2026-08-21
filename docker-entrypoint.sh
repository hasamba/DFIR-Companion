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

  # mkdir + recursively hand a whole app-dedicated tree to node (creating it if missing, migrating
  # a legacy root-owned one). Safe to recurse: these are the app's own directories, never a mount's
  # unrelated content.
  handoff_dir() { mkdir -p "$1" 2>/dev/null || true; chown_tree "$1"; }
  # The GLOBAL store subdirectories the server creates beside the cases root (runtimeStores.ts);
  # team-auth lives at DFIR_AUTH_DATA_DIR or a sibling .dfir-auth-<hash>.
  KNOWN_STORES="bundles dashboard-views diagnostics importers incident-types kev logs notifications nsrl report-templates tagger templates tools updates velociraptor whitelist"

  # /out holds the pre-built add-on the root cp above wrote; the server never writes it, but the
  # HOST user manages ./addon, so hand it over — via chown_tree, never `chown -R`, so a symlink
  # planted here can never redirect the chown into /app.
  if [ -d /out ]; then chown_tree /out; fi

  # Hand over the evidence/case store itself ONCE (a legacy root-written tree and large evidence
  # dirs both need the recursive walk). The parent handling below never re-walks this subtree.
  cases_root="$(abspath "${DFIR_CASES_ROOT:-/data/cases}")"
  handoff_dir "$cases_root"

  # The server also creates the global stores as subdirectories of the cases root's PARENT. Rather
  # than chown the whole parent (which on a shared mount would rewrite unrelated files, and would
  # re-walk the cases subtree), hand over each KNOWN store dir individually — never the parent's
  # other contents, and never the cases subtree twice.
  data_root="$(dirname "$cases_root")"
  case "$data_root" in
    /app | /app/*)
      echo "dfir-entrypoint: DFIR_CASES_ROOT=${DFIR_CASES_ROOT:-/data/cases} resolves under the root-owned /app code tree ($cases_root); its sibling stores (logs, templates, team-auth) will be unwritable — set DFIR_CASES_ROOT to an absolute path on a mounted volume (e.g. /data/cases)" >&2
      ;;
    / | . | "")
      # No dedicated parent (e.g. DFIR_CASES_ROOT=/cases): the server scatters stores into '/',
      # which must not be chowned. PRE-CREATE each known store (and the team-auth dir, whose name
      # hashes the resolved cases root) as node-owned so the server never needs to write '/'.
      for name in $KNOWN_STORES; do handoff_dir "/$name"; done
      if [ -z "${DFIR_AUTH_DATA_DIR:-}" ]; then
        auth_hash="$(printf '%s' "$cases_root" | sha256sum 2>/dev/null | cut -c1-12)"
        [ -n "$auth_hash" ] && handoff_dir "/.dfir-auth-$auth_hash"
      fi
      echo "dfir-entrypoint: DFIR_CASES_ROOT=${DFIR_CASES_ROOT:-/data/cases} has no dedicated parent; global stores are placed directly in '/' (non-persistent) — prefer a subdirectory of a mounted volume (e.g. /data/cases)" >&2
      ;;
    *)
      # A writable parent (the dedicated /data, or a custom mount): hand over the directory ENTRY
      # so the server can create NEW stores, then migrate any EXISTING known store or legacy
      # .dfir-auth-* to node — never recursing the parent's unrelated content, never re-walking
      # the cases subtree.
      chown -h node:node "$data_root" 2>/dev/null || true
      for name in $KNOWN_STORES; do
        if [ -e "$data_root/$name" ]; then chown_tree "$data_root/$name"; fi
      done
      for auth in "$data_root"/.dfir-auth-*; do
        if [ -e "$auth" ]; then chown_tree "$auth"; fi
      done
      ;;
  esac

  # Configured writable-store OVERRIDES that may live OUTSIDE data_root. Each is resolved the way
  # the server resolves it (absolute as-is, else relative to the cases parent — no ~ expansion,
  # matching authFactory/runtimeStores) and handed over as an app-dedicated tree.
  if [ -n "${DFIR_AUTH_DATA_DIR:-}" ]; then
    case "$DFIR_AUTH_DATA_DIR" in /*) d="$DFIR_AUTH_DATA_DIR" ;; *) d="$data_root/$DFIR_AUTH_DATA_DIR" ;; esac
    handoff_dir "$d"
  fi
  if [ -n "${DFIR_IMPORTERS_DIR:-}" ]; then
    case "$DFIR_IMPORTERS_DIR" in /*) d="$DFIR_IMPORTERS_DIR" ;; *) d="$data_root/$DFIR_IMPORTERS_DIR" ;; esac
    handoff_dir "$d"
  fi

  # OCR cache (app-dedicated; default /data/ocr-cache). No ~ expansion — ocrRedact.ts reads it raw.
  ocr_cache="${DFIR_OCR_CACHE:-/data/ocr-cache}"
  case "$ocr_cache" in /*) : ;; *) ocr_cache="$(realpath -m "$ocr_cache" 2>/dev/null || echo "$(pwd)/$ocr_cache")" ;; esac
  handoff_dir "$ocr_cache"

  # The Settings/setup .env dir must be writable so POST /settings/env's atomic write succeeds.
  env_file="${DFIR_ENV_FILE:-/data/companion.env}"
  case "$env_file" in /*) : ;; *) env_file="$(realpath -m "$env_file" 2>/dev/null || echo "$(pwd)/$env_file")" ;; esac
  env_dir="$(dirname "$env_file")"
  mkdir -p "$env_dir" 2>/dev/null || true
  chown -h node:node "$env_dir" 2>/dev/null || true

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
