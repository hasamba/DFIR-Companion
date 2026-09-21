// Named-destination facts as structured tags on a prompt row (#1502).
//
// The model reads each event through a 240-character head-and-tail render (promptDescription.ts).
// On INC-2026-033 that cut fell exactly on the facts an analyst asks about first: `mega:exfil` sat
// at character ~300 of the rclone row, the mshta URL at ~330, and the Metasploit port was never in
// the description at all — the importer clipped ScriptBlockText, and the port survived only in
// `message`, which no renderer read. The findings then said "destination unknown", "port unknown".
//
// So the facts are pulled out deterministically and appended as tags after the prose, beside
// <host:> / <proc:> / <net:> (synthEvidence.ts). A tag survives the cut because it is never inside
// it. Emits nothing for a row that names nothing, so a bare row costs no tokens.
//
// WHAT A TAG CLAIMS. A fact read from the row's own command line is operational: `<url:…>` is what
// the process fetched, `<dest:…>` is where rclone copied to. A fact read from prose — a script
// block, a description — is only MENTIONED there, and its tag says so (`<mentions-url:…>`,
// `<mentions-endpoint:…>`), so the model does not turn a string in a script into a connection.
// Secrets inside a URL (userinfo password, signed-link and token query parameters) are redacted
// before the tag is built — the same one-way rule the anonymizer applies (Codex code review).
//
// PURE — no I/O. Not a prompt constant: the eval change gate hashes only prompts/*.ts.

import type { ForensicEvent } from "./stateTypes.js";
import { splitDerivedNotes } from "./derivedNote.js";

/** The whole tag block — whole tags are dropped past this, never sliced. */
export const DESTINATION_TAGS_MAX = 200;
const URL_MAX = 120;
const MAX_URLS = 3;
const MAX_ENDPOINTS = 4;
/** A script block can run to tens of KB; the named endpoints are in its head when they exist. */
const MESSAGE_SCAN = 6000;
export const URL_SECRET_PLACEHOLDER = "[redacted]";

// `;`, `,` and `|` are legal URL characters and common command separators; a command line is the
// more likely reading, so `iwr http://h/a;whoami` yields `http://h/a`, not a URL ending in whoami.
const URL_RE = /https?:\/\/[^\s'"<>()[\]^;,|]+/giu;
const ENDPOINT_RE = /(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?![\w.])/gu;
/** A word within 40 characters of an endpoint that says what the author thought it was. */
const C2_CONTEXT_RE = /\b(c2|c&c|lhost|rhost|callback|beacon|listener|meterpreter)\b/iu;
/** …unless the same span negates it: "not C2", "no beacon". */
const C2_NEGATED_RE =
  /\b(not|no|never|non)\b[^.;]{0,12}\b(c2|c&c|lhost|rhost|callback|beacon|listener|meterpreter)\b/iu;
const RCLONE_TOKEN_RE = /(?:^|[\\/=])rclone(?:\.exe)?$/iu;
const DIRECTIONAL_VERBS = new Set(["copy", "sync", "move", "copyto", "moveto"]);
const RCLONE_VERBS = new Set([
  ...DIRECTIONAL_VERBS,
  "copyurl",
  "mount",
  "serve",
  "ls",
  "lsd",
  "lsf",
  "lsl",
  "lsjson",
  "cat",
  "check",
  "size",
  "tree",
  "ncdu",
]);
const SECRET_PARAM_RE =
  /^(sig|signature|token|access_token|id_token|refresh_token|key|apikey|api_key|sas|se|sv|sp|st|skoid|sktid|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|authorization|auth|password|passwd|pwd|secret|client_secret|code)$/iu;

const clean = (v: string): string => v.replace(/[<>\u0000-\u001f]/gu, "").trim();

type Source = { text: string; kind: "command" | "text" };

/** The text a row's facts live in: the command line, the base description, the head of the message. */
function factSources(e: ForensicEvent): Source[] {
  const out: Source[] = [];
  if (e.commandLine) out.push({ text: e.commandLine, kind: "command" });
  out.push({ text: splitDerivedNotes(e.description).base, kind: "text" });
  if (e.message) out.push({ text: e.message.slice(0, MESSAGE_SCAN), kind: "text" });
  return out;
}

/** Shell-style tokens: quotes group, everything else splits on whitespace. */
function tokenize(cmd: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/gu;
  for (const m of cmd.matchAll(re)) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

// `mega:exfil`, `b2:bucket/dir`, `mega:` — a name, a colon, and a path that does not start with a
// slash. `X:\` and `C:/` are Windows drives; a one-letter name with NOTHING after the colon is a
// drive root too (`X:`), while `m:loot` is a one-letter remote with a path.
function rcloneRemote(token: string): string | null {
  const m = /^([A-Za-z][\w-]{0,31}):(?![\\/])(.*)$/u.exec(token);
  if (!m) return null;
  if (m[1].length === 1 && m[2] === "") return null;
  return token;
}

// The verb of an rclone INVOCATION: the first non-option token after an rclone executable token,
// skipping `--flag` tokens and their values. A verb that precedes the executable belongs to an
// outer shell — `cmd /c copy rclone.exe mega:x` is a Windows copy, not an rclone one — and a
// mention of rclone with no verb after it is a mention.
function rcloneVerbAt(tokens: readonly string[]): number {
  for (let i = 0; i < tokens.length; i++) {
    if (!RCLONE_TOKEN_RE.test(tokens[i])) continue;
    let afterFlag = false;
    for (let j = i + 1; j < tokens.length; j++) {
      const t = tokens[j];
      if (t.startsWith("-")) {
        afterFlag = !t.includes("=");
        continue;
      }
      if (afterFlag) {
        afterFlag = false;
        continue;
      }
      if (RCLONE_VERBS.has(t.toLowerCase())) return j;
      break;
    }
  }
  return -1;
}

function rcloneTags(text: string): string[] {
  if (!/\brclone\b/iu.test(text)) return [];
  const tokens = tokenize(text);
  const verbAt = rcloneVerbAt(tokens);
  if (verbAt < 0) return [];
  const verb = tokens[verbAt].toLowerCase();
  // Operands are the run of non-option tokens right after the verb; the first `--flag` ends it,
  // which is what keeps `--config rclone.conf --transfers 8` from reading as more operands.
  const operands: string[] = [];
  for (const t of tokens.slice(verbAt + 1)) {
    if (t.startsWith("-")) break;
    operands.push(t);
  }
  const remotes = operands.filter((t) => rcloneRemote(t));
  if (!remotes.length) return [];
  if (DIRECTIONAL_VERBS.has(verb) && operands.length >= 2) {
    const dst = operands[operands.length - 1];
    // The destination is the LAST operand. A remote there is where data went; a remote in the
    // source slot is where it came from, and is named as a remote, not a destination.
    return remotes.map((t) => (t === dst ? `<dest:${clean(t)}>` : `<rclone-remote:${clean(t)}>`));
  }
  return remotes.map((t) => `<rclone-remote:${clean(t)}>`);
}

const stripTrailing = (u: string): string => u.replace(/[.!?:]+$/u, "");

/** The URL with its userinfo password and any token-bearing query/fragment parameter redacted. */
export function redactUrlSecrets(u: string): string {
  let out = u.replace(/^([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^\s@/]+)(@)/iu, `$1${URL_SECRET_PLACEHOLDER}$3`);
  out = out.replace(/([?&#])([^=&#]+)=([^&#]*)/gu, (m, sep: string, k: string) =>
    SECRET_PARAM_RE.test(k) ? `${sep}${k}=${URL_SECRET_PLACEHOLDER}` : m,
  );
  return out;
}

function urlTags(sources: readonly Source[]): { tags: string[]; urls: string[] } {
  const found: { url: string; kind: Source["kind"] }[] = [];
  for (const s of sources) {
    for (const m of s.text.matchAll(URL_RE)) {
      const u = stripTrailing(m[0]);
      if (u.length > "http://x".length && !found.some((f) => f.url === u))
        found.push({ url: u, kind: s.kind });
    }
  }
  const kept = found.slice(0, MAX_URLS);
  return {
    urls: found.map((f) => f.url),
    tags: kept.map(({ url, kind }) => {
      const shown = redactUrlSecrets(url);
      const value = clean(shown.length > URL_MAX ? shown.slice(0, URL_MAX) + "…" : shown);
      return `<${kind === "command" ? "url" : "mentions-url"}:${value}>`;
    }),
  };
}

/** Up to 40 characters each side of a match, cut at the line — the next line's label is not this one's. */
function sameLineAround(t: string, at: number, len: number): string {
  const before =
    t
      .slice(Math.max(0, at - 40), at)
      .split(/[\r\n]/u)
      .pop() ?? "";
  const after = t.slice(at + len, at + len + 40).split(/[\r\n]/u)[0] ?? "";
  return `${before} ${after}`;
}

const validOctets = (ip: string): boolean => ip.split(".").every((o) => Number(o) <= 255);

function endpointTags(e: ForensicEvent, sources: readonly Source[], urls: readonly string[]): string[] {
  const own = e.dstIp && typeof e.port === "number" ? `${e.dstIp}:${e.port}` : "";
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const s of sources) {
    for (const m of s.text.matchAll(ENDPOINT_RE)) {
      const pair = `${m[1]}:${m[2]}`;
      const port = Number(m[2]);
      if (port < 1 || port > 65535 || !validOctets(m[1])) continue;
      // Already stated: by the row's own <net:> tag, or inside a URL captured above.
      if (pair === own || seen.has(pair) || urls.some((u) => u.includes(pair))) continue;
      seen.add(pair);
      const around = sameLineAround(s.text, m.index ?? 0, m[0].length);
      const label = C2_CONTEXT_RE.test(around) && !C2_NEGATED_RE.test(around) ? " (labelled c2)" : "";
      const local = m[1].startsWith("127.") || m[1] === "0.0.0.0";
      const kind = `${s.kind === "command" ? "" : "mentions-"}${local ? "local-endpoint" : "endpoint"}`;
      tags.push(`<${kind}:${pair}${label}>`);
      if (seen.size >= MAX_ENDPOINTS) return tags;
    }
  }
  return tags;
}

/**
 * The destination facts a row names, as whole tags: `<dest:mega:exfil>` / `<rclone-remote:…>`,
 * `<url:…>` / `<mentions-url:…>`, `<endpoint:ip:port>` / `<mentions-endpoint:…>` (and the
 * `local-` forms for loopback). Deduped, sanitised, and bounded by dropping whole tags past
 * DESTINATION_TAGS_MAX. [] when the row names nothing.
 */
export function renderDestinationTags(e: ForensicEvent): string[] {
  const sources = factSources(e);
  const { tags: urlList, urls } = urlTags(sources);
  // rclone operands are positional, so each source is parsed on its own — joining them would make
  // the next source's first word the "destination".
  const rclone = sources.map((s) => rcloneTags(s.text)).find((t) => t.length) ?? [];
  const all = [...rclone, ...urlList, ...endpointTags(e, sources, urls)];
  const out: string[] = [];
  let used = 0;
  for (const tag of all) {
    const cost = tag.length + (out.length ? 1 : 0);
    if (used + cost > DESTINATION_TAGS_MAX) continue;
    out.push(tag);
    used += cost;
  }
  return out;
}
