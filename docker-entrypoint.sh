#!/bin/sh
set -e

# The browser add-on (extension) runs INSIDE your browser, not in this container. It is copied
# to /out so you can load it via your browser's Extensions page -> "Load unpacked" ->
# ./addon/dist on the host (mapped to /out here). The copy always runs UNPRIVILEGED — /out is
# writable by the (potentially compromised) server, and a root cp would follow a destination
# symlink planted there (e.g. dfir-companion-extension.zip -> /app/companion/dist/server.js)
# into the root-owned code tree on the next boot. So: the root path below does it via setpriv
# AFTER deciding the run user; the already-unprivileged path copies here.
copy_addon() {
  if [ -d /opt/dfir-extension ] && [ -d /out ]; then
    cp -R /opt/dfir-extension/. /out/ 2>/dev/null || true
  fi
}
if [ "$(id -u)" != "0" ]; then
  copy_addon
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
  node_gid="$(id -g node)"
  node_home=/home/node

  # Hand a tree to the RUN user (see run_uid below), chowning ONLY the inodes not already owned by
  # it — so a correctly-owned tree costs a stat-walk, not a full re-chown, and (crucially) a host
  # operator's own files are skipped entirely when we run AS that operator. `-h` plus find's default
  # no-follow-symlink traversal mean a compromised server cannot plant a symlink that a later root
  # chown would dereference into a protected target (e.g. the /app code tree).
  chown_tree() { find "$1" ! -uid "$run_uid" -exec chown -h "$run_uid:$run_gid" {} + 2>/dev/null || true; }
  # Expand a leading ~ to node's POST-DROP home (matching the server's expandHome()), then
  # NORMALIZE via realpath -m: a relative path resolves against /app/companion (the working dir the
  # server anchors relative roots to) and, crucially, `..` segments are collapsed so an absolute
  # path like /data/../cases can never make dirname yield /data/.. and chown '/'.
  abspath() {
    _p="$1"
    case "$_p" in
      "~") _p="$node_home" ;;
      "~/"*) _p="$node_home/${_p#\~/}" ;;
    esac
    realpath -m "$_p" 2>/dev/null || printf '%s' "$_p"
  }
  # Like abspath but WITHOUT ~ expansion, for the vars the server reads raw (DFIR_OCR_CACHE,
  # DFIR_OCR_DEBUG_DIR, DFIR_ENV_FILE) — still normalized so `..` cannot escape.
  abspath_raw() { realpath -m "$1" 2>/dev/null || printf '%s' "$1"; }
  # LEXICALLY normalize an absolute path exactly like Node's path.resolve — collapse '.', '..' and
  # repeated slashes WITHOUT dereferencing symlinks. authFactory hashes path.resolve(casesRoot)
  # (not realpath), so the team-auth dir name must be derived from this, never from the symlink-
  # dereferenced realpath used for chown targets, or the two would diverge on a symlinked root.
  lexical_norm() {
    _out=""
    _oldifs="$IFS"
    IFS=/
    for _seg in $1; do
      case "$_seg" in
        "" | .) ;;
        ..) _out="${_out%/*}" ;;
        *) _out="$_out/$_seg" ;;
      esac
    done
    IFS="$_oldifs"
    printf '%s' "${_out:-/}"
  }

  # Confinement: several handoff paths come from DASHBOARD-writable settings (DFIR_OCR_*, log,
  # importer, auth) persisted to the node-writable dotenv file. Without this, a compromised node
  # could set one to '/' or '/app' and have the NEXT root startup chown the whole filesystem or the
  # code tree to itself — negating the privilege drop. Refuse to chown the filesystem root, the
  # /app code tree, or any OS system directory; genuine data locations (/data, /mnt/*, /srv/*, a
  # custom /evidence, …) are allowed.
  deny_chown() {
    case "$1" in
      "" | /) return 0 ;;
      # /app is the server code; /opt holds the bundled extension the entrypoint copies to /out —
      # both are code the server must never be able to rewrite. chown_tree recurses, so denying an
      # ancestor (e.g. /opt) also protects everything under it (/opt/dfir-extension).
      /app | /app/* | /opt | /opt/*) return 0 ;;
      /bin | /bin/* | /boot | /boot/* | /dev | /dev/* | /etc | /etc/* | /lib | /lib/* | /lib64 | /lib64/* | /proc | /proc/* | /root | /root/* | /run | /run/* | /sbin | /sbin/* | /sys | /sys/* | /usr | /usr/* | /var | /var/*) return 0 ;;
      *) return 1 ;;
    esac
  }
  # mkdir + recursively hand an app-dedicated tree over (creating it if missing, migrating a
  # legacy root-owned one). Normalizes and confines first. TRUSTED variant: only for paths the
  # OPERATOR configured in the real container environment (or the image defaults) — never for a
  # value read from the dashboard-writable dotenv file.
  handoff_dir() {
    _d="$(abspath_raw "$1")"
    if deny_chown "$_d"; then
      echo "dfir-entrypoint: refusing to hand off '$1' -> '$_d' (filesystem root, /app code tree, or a system directory); ignoring" >&2
      return 0
    fi
    mkdir -p "$_d" 2>/dev/null || true
    chown_tree "$_d"
  }
  # Hand over just a directory ENTRY (not its contents) — for a possibly-shared dir the server only
  # needs to create a file in (an explicit log dir, the .env dir). Same confinement; trusted-source
  # values only.
  handoff_entry() {
    _d="$(abspath_raw "$1")"
    if deny_chown "$_d"; then
      echo "dfir-entrypoint: refusing to hand off '$1' -> '$_d' (filesystem root, /app code tree, or a system directory); ignoring" >&2
      return 0
    fi
    mkdir -p "$_d" 2>/dev/null || true
    chown -h "$run_uid:$run_gid" "$_d" 2>/dev/null || true
  }
  # UNTRUSTED variants, for paths whose value came from the dotenv file the unprivileged server can
  # WRITE (Settings). Root must never transfer ownership of pre-existing data on the say-so of that
  # file — a compromised server could name another bind mount (/mnt, /evidence) and wait for a
  # restart, a confused deputy the deny-list alone cannot close. Rules: inside /data (the image's
  # dedicated data tree) recursion stays enabled — there is nothing there but the app's own data;
  # elsewhere, CREATE the directory when absent (a fresh empty dir disowns nothing) and hand over
  # only that entry, but leave an EXISTING dir not already owned by the run user untouched, telling
  # the operator to set the variable in the real container environment for an actual migration.
  handoff_dir_untrusted() {
    _d="$(abspath_raw "$1")"
    if deny_chown "$_d"; then
      echo "dfir-entrypoint: refusing to hand off '$1' -> '$_d' (filesystem root, /app code tree, or a system directory); ignoring" >&2
      return 0
    fi
    case "$_d" in
      /data | /data/*)
        mkdir -p "$_d" 2>/dev/null || true
        chown_tree "$_d"
        return 0
        ;;
    esac
    if [ ! -e "$_d" ]; then
      mkdir -p "$_d" 2>/dev/null || true
      chown -h "$run_uid:$run_gid" "$_d" 2>/dev/null || true
    elif [ "$(stat -c %u "$_d" 2>/dev/null)" != "$run_uid" ]; then
      echo "dfir-entrypoint: not changing ownership of existing '$_d' — its location comes from the dashboard-writable settings file; set the variable in the container environment (compose/docker -e) to hand it off" >&2
    fi
  }
  handoff_entry_untrusted() { handoff_dir_untrusted "$1"; }
  # The GLOBAL store subdirectories the server creates beside the cases root (runtimeStores.ts);
  # team-auth lives at DFIR_AUTH_DATA_DIR or a sibling .dfir-auth-<hash>.
  KNOWN_STORES="bundles dashboard-views diagnostics importers incident-types kev logs notifications nsrl report-templates tagger templates tools updates velociraptor whitelist"

  # Writable-path overrides may be saved through Settings into the dotenv file that the server
  # loads only AFTER the privilege drop, so they are absent from THIS process's environment. Read
  # them from that file here too, so a Settings-configured (possibly root-owned) auth/importer/log/
  # OCR path is still handed to node. Process env wins (matches dotenv's no-override default), and
  # the parser mirrors dotenv: optional `export`, single/double quotes, and inline `# comments`.
  env_file="$(abspath_raw "${DFIR_ENV_FILE:-/data/companion.env}")"
  env_file_get() {
    [ -f "$env_file" ] || return 0
    # dotenv grammar: optional leading spaces, optional `export `, KEY, optional spaces around `=`,
    # optional spaces before the value.
    line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=" "$env_file" 2>/dev/null | tail -1)"
    [ -n "$line" ] || return 0
    v="$(printf '%s' "$line" | sed -E "s/^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=[[:space:]]*//")"
    case "$v" in
      \"*) v="${v#\"}"; v="${v%%\"*}" ;;
      \'*) v="${v#\'}"; v="${v%%\'*}" ;;
      *) v="$(printf '%s' "$v" | sed -E 's/[[:space:]]+#.*$//; s/[[:space:]]+$//')" ;;
    esac
    printf '%s' "$v"
  }
  # Track PROVENANCE while merging: a value already present in the real environment (operator- or
  # image-set) is trusted; one that only exists in the dotenv file is dashboard-writable and gets
  # the untrusted handoff rules above. In the shipped image DFIR_CASES_ROOT / DFIR_OCR_CACHE /
  # DFIR_ENV_FILE are Dockerfile ENVs, so they are always trusted unless an operator strips them.
  from_env_file=""
  load_env_file_var() {
    eval "_cur=\${$1:-}"
    [ -n "$_cur" ] && return 0
    _v="$(env_file_get "$1")"
    [ -n "$_v" ] || return 0
    eval "$1=\$_v"
    from_env_file="$from_env_file $1"
  }
  is_from_env_file() { case " $from_env_file " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
  for _var in DFIR_CASES_ROOT DFIR_AUTH_DATA_DIR DFIR_IMPORTERS_DIR DFIR_LOG_DIR DFIR_OCR_CACHE DFIR_OCR_DEBUG_DIR; do
    load_env_file_var "$_var"
  done

  # Resolve the cases root two ways: the DEREFERENCED real dir (for chowning — following symlinks to
  # the actual inode), and a LEXICAL path (for deriving parent/sibling/auth locations — the server
  # uses path.resolve/dirname without dereferencing, so its global stores sit beside the lexical
  # path). They differ only when the cases root itself is a symlink.
  cases_root="$(abspath "${DFIR_CASES_ROOT:-/data/cases}")"
  cases_raw="${DFIR_CASES_ROOT:-/data/cases}"
  case "$cases_raw" in
    "~") cases_raw="$node_home" ;;
    "~/"*) cases_raw="$node_home/${cases_raw#\~/}" ;;
  esac
  case "$cases_raw" in /*) : ;; *) cases_raw="/app/companion/$cases_raw" ;; esac
  cases_lexical="$(lexical_norm "$cases_raw")"
  data_root="$(dirname "$cases_lexical")"

  # Run the server AS THE OWNER of the case data. A host operator whose uid differs from the image's
  # `node` (1000) then keeps ownership of their bind-mounted ./cases and ./addon: chown_tree targets
  # run_uid and skips inodes already owned by it, so none of the operator's own files are touched.
  # Only a ROOT-owned root (a fresh Docker-created mount, or the legacy root image's data) falls
  # back to `node`, where chowning is safe because there is no host-owned data to disown.
  mkdir -p "$cases_root" 2>/dev/null || true
  run_uid="$(stat -c '%u' "$cases_root" 2>/dev/null || printf '0')"
  if [ -z "$run_uid" ] || [ "$run_uid" = "0" ]; then
    run_uid="$node_uid"
  fi
  # NEVER adopt the mount's GID: a numeric host GID has unrelated, possibly privileged semantics
  # inside this image (42 is shadow, 0 is root), so a mount owned by 1001:42 would hand the
  # evidence parser group-readable /etc/shadow. The run group is always the image's unprivileged
  # `node` group; the mount owner still has full access through the preserved UID.
  run_gid="$node_gid"

  # /out holds the pre-built add-on; the server never writes it, but the HOST user manages
  # ./addon, so hand it over — via chown_tree, never `chown -R`, so a symlink planted here can
  # never redirect the chown into /app — and only THEN copy the add-on in, as the run user, so
  # the copy cannot be deputized through a planted destination symlink either (an unprivileged
  # cp that follows one just gets EACCES on the root-owned target).
  if [ -d /out ]; then
    chown_tree /out
    setpriv --reuid="$run_uid" --regid="$run_gid" --clear-groups \
      sh -c 'if [ -d /opt/dfir-extension ]; then cp -R /opt/dfir-extension/. /out/ 2>/dev/null || true; fi' || true
  fi

  # Hand over the evidence/case store itself ONCE (a legacy root-written tree and large evidence
  # dirs both need the recursive walk). The parent handling below never re-walks this subtree.
  # Trust follows the value's provenance: a dotenv-sourced cases root (possible only when the
  # operator stripped the image's DFIR_CASES_ROOT ENV) gets the no-disown untrusted rules.
  if is_from_env_file DFIR_CASES_ROOT; then cases_handoff=handoff_dir_untrusted; else cases_handoff=handoff_dir; fi
  "$cases_handoff" "$cases_root"

  # The server also creates the global stores as subdirectories of the cases root's PARENT. NEVER
  # chown the parent itself: on a shared bind mount that would let the server rename or delete
  # unrelated sibling entries. Instead PRE-CREATE and hand off each KNOWN store (and the team-auth
  # dir, whose name hashes the resolved cases root) individually — so the server writes only into
  # its own owned directories and never needs the parent writable. (A future store type not in this
  # list would need the parent writable; the default /data parent is node-owned from the image
  # build, so it still works there.)
  case "$data_root" in
    /app | /app/*)
      echo "dfir-entrypoint: DFIR_CASES_ROOT=${DFIR_CASES_ROOT:-/data/cases} resolves under the root-owned /app code tree ($cases_lexical); its sibling stores (logs, templates, team-auth) will be unwritable — set DFIR_CASES_ROOT to an absolute path on a mounted volume (e.g. /data/cases)" >&2
      ;;
    *)
      for name in $KNOWN_STORES; do "$cases_handoff" "${data_root%/}/$name"; done
      if [ -z "${DFIR_AUTH_DATA_DIR:-}" ]; then
        # authFactory: .dfir-auth-<sha256(path.resolve(casesRoot))[:12]> beside the lexically
        # resolved cases root — path.resolve does not dereference symlinks, so use cases_lexical.
        auth_hash="$(printf '%s' "$cases_lexical" | sha256sum 2>/dev/null | cut -c1-12)"
        [ -n "$auth_hash" ] && "$cases_handoff" "${data_root%/}/.dfir-auth-$auth_hash"
      fi
      case "$data_root" in
        / | . | "")
          echo "dfir-entrypoint: DFIR_CASES_ROOT=${DFIR_CASES_ROOT:-/data/cases} has no dedicated parent; global stores are placed directly in '/' (non-persistent) — prefer a subdirectory of a mounted volume (e.g. /data/cases)" >&2
          ;;
      esac
      ;;
  esac

  # Configured writable-store OVERRIDES that may live OUTSIDE data_root. Each is resolved the way
  # the server resolves it (absolute as-is, else relative to the cases parent — no ~ expansion,
  # matching authFactory/runtimeStores). handoff_dir confines each before chowning.
  if [ -n "${DFIR_AUTH_DATA_DIR:-}" ]; then
    case "$DFIR_AUTH_DATA_DIR" in /*) d="$DFIR_AUTH_DATA_DIR" ;; *) d="${data_root%/}/$DFIR_AUTH_DATA_DIR" ;; esac
    if is_from_env_file DFIR_AUTH_DATA_DIR; then handoff_dir_untrusted "$d"; else handoff_dir "$d"; fi
  fi
  if [ -n "${DFIR_IMPORTERS_DIR:-}" ]; then
    case "$DFIR_IMPORTERS_DIR" in /*) d="$DFIR_IMPORTERS_DIR" ;; *) d="${data_root%/}/$DFIR_IMPORTERS_DIR" ;; esac
    if is_from_env_file DFIR_IMPORTERS_DIR; then handoff_dir_untrusted "$d"; else handoff_dir "$d"; fi
  fi

  # OCR cache (app-dedicated; default /data/ocr-cache) and the optional OCR debug-dump dir — both
  # read raw by the server (no ~ expansion), each confined by trust-appropriate handoff.
  if is_from_env_file DFIR_OCR_CACHE; then handoff_dir_untrusted "${DFIR_OCR_CACHE:-/data/ocr-cache}"; else handoff_dir "${DFIR_OCR_CACHE:-/data/ocr-cache}"; fi
  if [ -n "${DFIR_OCR_DEBUG_DIR:-}" ]; then
    if is_from_env_file DFIR_OCR_DEBUG_DIR; then handoff_dir_untrusted "$DFIR_OCR_DEBUG_DIR"; else handoff_dir "$DFIR_OCR_DEBUG_DIR"; fi
  fi

  # The Settings/setup .env dir must be writable so POST /settings/env's atomic write succeeds.
  # (DFIR_ENV_FILE cannot come from the dotenv file it locates, so it is always trusted.)
  handoff_entry "$(dirname "$env_file")"

  # An explicit DFIR_LOG_DIR may point at a SHARED host log directory: the logger only needs to
  # CREATE its session file there, so hand over the directory entry only — never its (possibly
  # unrelated) contents. (Unset → logs/ beside the cases root, already handed over above.)
  if [ -n "${DFIR_LOG_DIR:-}" ]; then
    if is_from_env_file DFIR_LOG_DIR; then handoff_entry_untrusted "$(abspath "$DFIR_LOG_DIR")"; else handoff_entry "$(abspath "$DFIR_LOG_DIR")"; fi
  fi
  # setpriv execs in place, so Node stays PID 1 and docker stop signals it directly. --clear-groups
  # sheds root's supplementary groups (and works for an arbitrary numeric run_uid that has no passwd
  # entry, unlike --init-groups). setpriv changes credentials but NOT HOME/USER/LOGNAME, so set HOME
  # explicitly (env, preserving DFIR_* config) — otherwise `~/…` paths would resolve under the
  # now-inaccessible /root. HOME stays /home/node so ~ expansion matches this entrypoint's; it is
  # only READ for path resolution (never written), so it is valid even when run_uid is not node.
  exec setpriv --reuid="$run_uid" --regid="$run_gid" --clear-groups \
    env HOME=/home/node USER=node LOGNAME=node node dist/server.js
fi

# Already unprivileged (e.g. a compose `user:` override): the operator owns mount
# permissions; hand off to the Node server as PID 1 so signals stop it cleanly.
exec node dist/server.js
