import { homedir, tmpdir } from "node:os";
import { escapeRegExp } from "./regexEscape.js";

/**
 * Strip absolute filesystem paths out of strings bound for an HTTP client (#250).
 *
 * Node's fs errors embed the whole path — `ENOENT: no such file or directory, open
 * '/home/alice/cases/INC-1/imports/0001_alerts.json'` — and the route `catch` blocks return
 * `err.message` verbatim. On an unauthenticated localhost API that hands any caller the cases-root
 * location, the operator's username, and the install layout: reconnaissance for a file-targeting
 * attack (symlink, env injection). Removing `casesRoot` from /diagnostics accomplishes nothing while
 * the first failed import prints it back out.
 *
 * Only the CLIENT-facing copy is redacted. `serverLogger` keeps the raw message, so an operator
 * debugging from the console or the log file loses no fidelity — see the callers in server.ts.
 */

const PLACEHOLDER = "<path>";

/** Path characters: up to whitespace, a quote, or a separator. Deliberately narrow, so a path at
 * the end of a sentence doesn't swallow the trailing prose along with it. */
const SEG = String.raw`[^\s/\\:*?"'<>|]+`;

/** Schemes copied through untouched: a provider error legitimately carries its endpoint, and
 * `ai.baseUrl` is already a deliberate diagnostics field, so flattening it to <path> would make
 * those errors unactionable. `file:` is deliberately absent — that is a filesystem path in a
 * scheme's clothing and gets redacted like any other. */
const URL_RE = /\b(?!file:)[a-z][a-z0-9+.-]*:\/\/[^\s'"<>]+/gi;

/**
 * First segment of an absolute POSIX path that is plausibly a FILESYSTEM path. Without this
 * allowlist a message naming an HTTP route ("expected /cases/:id/import") flattens to <path> and
 * stops being actionable — routes and filesystem paths are both slash-delimited absolutes, and
 * only the leading segment tells them apart.
 */
const FS_TOP_LEVEL = [
  "home",
  "Users",
  "root",
  "var",
  "tmp",
  "opt",
  "srv",
  "mnt",
  "media",
  "etc",
  "usr",
  "private",
  "data",
  "app",
  "Volumes",
  "Applications",
  "Library",
  "System",
  "proc",
  "dev",
  "run",
];

const POSIX_FS_PATH_RE = new RegExp(String.raw`/(?:${FS_TOP_LEVEL.join("|")})(?:/${SEG})*/?`, "g");

/** `C:\dir\file` and UNC `\\host\share\file`. Both require at least one segment, so a bare "C:" in
 * prose is left alone. */
const WINDOWS_FS_PATH_RE = new RegExp(String.raw`(?:[A-Za-z]:\\|\\\\)${SEG}(?:\\${SEG})*\\?`, "g");

/** Known roots on THIS machine, longest first so a nested root wins over its parent. Relative and
 * single-character roots are dropped — replacing "/" globally would shred every message. */
function knownRoots(extraRoots: readonly string[]): string[] {
  return [...extraRoots, homedir(), tmpdir(), process.cwd()]
    .filter((r) => typeof r === "string" && r.length > 1 && (r.startsWith("/") || /^[A-Za-z]:[\\/]/.test(r)))
    .sort((a, b) => b.length - a.length);
}

function redactOutsideUrls(text: string, roots: readonly string[]): string {
  let out = text;
  // Configured roots first: they catch an installation living somewhere FS_TOP_LEVEL doesn't
  // know about (a DFIR_CASES_ROOT of /evidence/cases, say).
  for (const root of roots) {
    out = out.replace(new RegExp(`${escapeRegExp(root)}(?:[/\\\\]${SEG})*[/\\\\]?`, "g"), PLACEHOLDER);
  }
  return out.replace(WINDOWS_FS_PATH_RE, PLACEHOLDER).replace(POSIX_FS_PATH_RE, PLACEHOLDER);
}

/**
 * Replace absolute filesystem paths in `text` with `<path>`, leaving http(s)-style URLs intact.
 * `extraRoots` adds machine-specific roots to redact wholesale — pass `store.casesRoot`.
 */
export function redactPaths(text: string, extraRoots: readonly string[] = []): string {
  if (!text) return text;
  const roots = knownRoots(extraRoots);
  // Walk the string so a URL's own path segments are never mistaken for a filesystem path: copy
  // each protected URL through verbatim and redact only the gaps between them.
  let out = "";
  let last = 0;
  for (const m of text.matchAll(URL_RE)) {
    const at = m.index ?? 0;
    out += redactOutsideUrls(text.slice(last, at), roots);
    out += m[0];
    last = at + m[0].length;
  }
  return out + redactOutsideUrls(text.slice(last), roots);
}

/** `redactPaths` over an unknown thrown value — the shape every `catch` block here deals with. */
export function redactedErrorMessage(err: unknown, extraRoots: readonly string[] = []): string {
  return redactPaths((err as Error)?.message ?? String(err), extraRoots);
}
