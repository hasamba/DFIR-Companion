// Why a Velociraptor launch failed, in the server's own words.
//
// The `velociraptor query` CLI does NOT fail loudly when VQL fails. `hunt()` and `collect_client()`
// report a refusal by writing to the scope log and returning NULL: the process exits 0, stdout holds
// one `{"Hunt": null}` row, and stderr is EMPTY unless the binary was started with `-v`. So a caller
// that reads rows alone can only say "no hunt id came back" and guess at the cause — which is exactly
// what the Companion did, for the whole life of the feature, and its guess (an ACL) was usually wrong.
//
// spawnVqlOnce therefore runs the binary verbosely and keeps its stderr; these two pure functions turn
// that log into something an analyst can act on.

// One line of the verbose log: "[INFO] 2026-08-18T16:37:00Z hunt: Get \"…\": …".
const VELO_LOG_LINE_RE = /^\[(\w+)\]\s+\S+\s+(.*)$/;
// A VQL plugin's own scope log, which it writes as "<plugin_name>: <reason>" — a lowercase snake
// symbol and a colon. This is what distinguishes `hunt: …` from the startup chatter around it, with
// no list of plugin names to keep in sync.
const VQL_SCOPE_LOG_RE = /^[a-z_][a-z0-9_]*:\s+\S/;
const VQL_LOG_ERRORS_MAX = 600; // an error banner, not a log file

/**
 * Pull the DIAGNOSIS out of the CLI's stderr and leave the startup noise behind.
 *
 * Keeps: any line that is NOT a verbose log line (a plain error the binary printed itself — e.g. the
 * gRPC message-size failure, which must never be discarded), every non-INFO level, a plugin's scope
 * log, and a compile error (which carries "ERROR:" inline). Returns "" when only noise is left.
 */
export function vqlLogErrors(stderr: string): string {
  const out: string[] = [];
  for (const raw of String(stderr || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = VELO_LOG_LINE_RE.exec(line);
    if (!m) {
      out.push(line); // not a log line at all — the binary's own error text
      continue;
    }
    const level = m[1].toUpperCase();
    const msg = m[2].trim();
    if (!msg) continue;
    if (level === "INFO" || level === "DEBUG") {
      if (!msg.includes("ERROR:") && !VQL_SCOPE_LOG_RE.test(msg)) continue; // startup chatter
    }
    if (!out.includes(msg)) out.push(msg); // one failure is often logged per statement
  }
  return out.join("; ").slice(0, VQL_LOG_ERRORS_MAX);
}

/**
 * What to tell the analyst when `hunt()` / `collect_client()` came back with no id.
 *
 * The old message guessed at ACLs. That guess was usually wrong and never actionable: on a real server
 * the api_client is often an administrator and the launch still fails, because Velociraptor resolves
 * every artifact's third-party tools while it compiles the request, and ONE tool with an unconfigured
 * download URL (the `todo.<tool>.download.url` placeholder that ships with e.g. Generic.Scanner.ThorZIP)
 * aborts the whole launch. So `reason` — the server's own log line, when we captured one — comes FIRST,
 * and the guesses come after it.
 */
export function noLaunchIdMessage(what: string, reason = ""): string {
  const said = reason.trim() ? ` — Velociraptor said: ${reason.trim()}` : "";
  return (
    `Velociraptor accepted the query but returned no ${what} id${said}.` +
    " Usual causes: an artifact needs a third-party tool whose download URL is not set on the server," +
    " the VQL references an artifact/plugin that does not exist, or the api_client role lacks START_HUNT."
  );
}

// Translate a known Velociraptor CLI error into an actionable message. Unlike our OWN
// maxOutputBytes/collectMaxOutputBytes caps (DFIR_VELOCIRAPTOR_*_OUTPUT — bound what we capture
// AFTER gRPC delivers it), the gRPC connection the `velociraptor query` CLI makes to the server
// enforces its own message-size ceiling, independent of both our caps and the server's own config.
// Per Velociraptor's source (config/proto/config.proto, ApiClientConfig.max_grpc_recv_size — "This
// is 4mb by default but you can increase it if you like"), this is a field in the CLIENT-side
// api_client.yaml — the exact file DFIR_VELOCIRAPTOR_API_CONFIG points to, NOT a CLI flag (an
// earlier version of this file tried `--max_message_size`, which does not exist and broke every
// query on some builds; NOT the server's Frontend.resources.max_upload_size either — that's a
// different data path, HTTP client uploads, not this gRPC query connection). No server restart
// needed: add `max_grpc_recv_size: <bytes>` as a top-level key in the api_client.yaml file.
export function translateVelociraptorError(stderr: string): string {
  if (!stderr) return stderr;
  if (/received message larger than max/i.test(stderr)) {
    return `${stderr} — raise this by adding "max_grpc_recv_size: 67108864" (or larger) as a top-level key in the api_client.yaml file your DFIR_VELOCIRAPTOR_API_CONFIG points to (Velociraptor's ApiClientConfig.max_grpc_recv_size, 4MB by default) — no CLI flag or server restart needed. Or narrow the artifact (fewer rows/hosts) so its output stays under the limit.`;
  }
  return stderr;
}
