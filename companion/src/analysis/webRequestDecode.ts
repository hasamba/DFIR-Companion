// Bounded decoding of web request fields, and the CONTEXTUAL attack shapes that fire on the
// decoded text (#930 item 3). Consulted by the combined-log importer the way secretSpillRules.ts
// is: a per-line signal that raises severity, adds a technique, and forks the aggregation key so
// the evidence survives aggregation.
//
// WHY DECODE. An access log stores the request target as the client sent it, and an attacker sends
// it encoded — `%2e%2e%2f` for `../`, `%3B` for `;`, `%2525` for a percent sign that decodes twice.
// Without decoding, traversal and command injection are invisible even to the spill rules. The
// decoder here is ITERATIVE (up to three layers) and BOUNDED: it never evaluates, never fetches,
// never normalises a path on disk, and never inspects more than MAX_FIELD characters — a field past
// the bound is not decoded at all; the importer reports it as `oversized` instead of silently
// scanning a prefix (a payload placed after a prefix window would otherwise be free).
//
// WHY CONTEXTUAL. Every family requires a STRUCTURE, never a token: `../` followed by a sensitive
// target, a shell separator followed by a tool with an argument or a recon command, `${jndi:` or a
// template expression with an operator, `union select` / `' or 1=1` / a timing call with an
// argument. `/bin/sh/docs`, `?filter=a|b`, `?q=select name from users` and `/docs/sleep(` are the
// benign shapes each rule is tested against. A REST field list (`fields=name|id`) is why the recon
// names split into two tiers: names that are plausible field identifiers fire after a bare pipe
// only with a flag or an absolute path.
//
// THE OUTCOME IS NOT IMPLIED. A match says "this request carried an attack shape"; the HTTP status
// beside it says what the server answered. A 200 does not prove execution and a 500 does not prove
// prevention — the importer states both and calls neither "compromise".
//
// Pure + table-driven + unit-tested. No AI.

import { createHash } from "node:crypto";

/** The per-field inspection bound: a field at or under it is decoded and scanned IN FULL. */
export const MAX_FIELD = 65_536;
const MAX_PASSES = 3;
const MATCH_MAX = 512; // the identity form of a match (feeds the aggregation digest)
const EXCERPT_MAX = 60; // the display form of a match

export interface DecodedTarget {
  original: string;
  decoded: string;
  /** How many decoding layers were peeled (0 = nothing was encoded). */
  passes: number;
  /** An invalid or unterminated escape was met and left as-is. */
  malformed: boolean;
}

export interface AttackMatch {
  family: string;
  /** The full regex match (≤ MATCH_MAX) — identity, never displayed raw. */
  match: string;
  /** Bounded, control-escaped display form. */
  excerpt: string;
}

export interface WebAttackSignal {
  families: string[];
  matches: AttackMatch[];
}

/** Clip a field to MAX_FIELD; `oversized` carries the TRUE length when it was clipped. */
export function clipField(text: string): { text: string; oversized: number | null } {
  return text.length > MAX_FIELD
    ? { text: text.slice(0, MAX_FIELD), oversized: text.length }
    : { text, oversized: null };
}

// C0 controls, DEL and C1 controls become visible `\xNN` tokens: a decoded NUL must never reach a
// description, a report or a prompt as a real byte (it blinds grep and truncates C strings).
export function escapeControlChars(text: string): string {
  return text.replace(/[\x00-\x1f\x7f-\x9f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);
}

const HEX2 = /^[0-9a-fA-F]{2}$/;
const HEX4 = /^[0-9a-fA-F]{4}$/;

// One decoding pass over one string: `%XX` and `%uXXXX` become their characters; `+` becomes a
// space only when `plusIsSpace` (the query part). An invalid or unterminated escape is copied
// through unchanged and flagged. Byte-wise: multi-byte UTF-8 sequences are assembled after the
// pass, and an invalid sequence becomes replacement characters rather than throwing.
function decodeOnce(
  text: string,
  plusIsSpace: boolean,
): { out: string; changed: boolean; malformed: boolean } {
  const bytes: number[] = [];
  let changed = false;
  let malformed = false;
  const flushText = (s: string): void => {
    for (const b of Buffer.from(s, "utf8")) bytes.push(b);
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "%") {
      if (text[i + 1] === "u" || text[i + 1] === "U") {
        const hex = text.slice(i + 2, i + 6);
        if (HEX4.test(hex)) {
          flushText(String.fromCharCode(parseInt(hex, 16)));
          i += 5;
          changed = true;
          continue;
        }
        malformed = true;
        flushText(c);
        continue;
      }
      const hex = text.slice(i + 1, i + 3);
      if (HEX2.test(hex)) {
        bytes.push(parseInt(hex, 16));
        i += 2;
        changed = true;
        continue;
      }
      malformed = true;
      flushText(c);
      continue;
    }
    if (c === "+" && plusIsSpace) {
      bytes.push(0x20);
      changed = true;
      continue;
    }
    flushText(c);
  }
  return { out: Buffer.from(bytes).toString("utf8"), changed, malformed };
}

/**
 * Peel up to three layers of URL encoding off a request target. The path and the query are decoded
 * separately so `+` means a space only in the query. Pure; never throws on garbage.
 */
export function decodeRequestTarget(text: string): DecodedTarget {
  const q = text.indexOf("?");
  let path = q >= 0 ? text.slice(0, q) : text;
  let query = q >= 0 ? text.slice(q + 1) : null;
  let passes = 0;
  let malformed = false;
  for (let n = 0; n < MAX_PASSES; n++) {
    const p = decodeOnce(path, false);
    // A literal `+` in the query means a space only as the client SENT it — on the first pass. A
    // `+` produced by decoding `%2B` is a plus sign, and turning it into a space on the next pass
    // corrupted `${7%2B7}` into `${7 7}` and hid it from the expression rule.
    const s = query === null ? null : decodeOnce(query, n === 0);
    malformed = malformed || p.malformed || (s?.malformed ?? false);
    if (!p.changed && !(s?.changed ?? false)) break;
    path = p.out;
    if (s) query = s.out;
    passes++;
  }
  return { original: text, decoded: query === null ? path : `${path}?${query}`, passes, malformed };
}

// ───────────── Attack shapes ─────────────
// Every regex is linear: no nested quantifiers over one class, no unbounded `.*` between anchors,
// and every repeat that follows a class is bounded. Where a regex would need a length cap to stay
// linear — "the value before the `;`", "the comment body" — the text is PARSED instead: a URL's
// query is split into values, and SQL comments are removed by a scan, so no cap exists to pad past.

const BT = "`";
// Shell separators inside a query VALUE — including a decoded newline: `foo%0Aid` is `foo` then `id`
// on its own line. `;` is a separator in a value; in a PATH it is matrix syntax and is not scanned.
const SEP = String.raw`(?:;|\|\||&&|\||\r?\n|` + BT + String.raw`|\$\()`;
const STRICT_SEP = String.raw`(?:;|\|\||&&|\r?\n|` + BT + String.raw`|\$\()`; // every separator but a bare pipe
const ARG = String.raw`[^\s;|&"'<>` + BT + String.raw`]{1,200}`; // one argument token, bounded
const PATH_ARG =
  String.raw`(?:[\/\\~]|[A-Za-z]:\\|\.{1,2}[\/\\]|\.\w)[^\s;|&"'<>` + BT + String.raw`]{0,200}`; // a path-shaped argument
const TAIL = String.raw`(?=$|[\s;|&"'` + BT + String.raw`)\x00-\x1f])`; // what may follow a direct command — never `=`
// A shell runs a QUOTED command name too (`;'id'`, `cmd="cat" /etc/passwd`), so every command
// token may be wrapped in one optional quote on each side.
const Q = String.raw`['"]?`;

// Interpreters and transfer tools fire with ANY argument; file readers (`cat`, `type`) only with a
// path-shaped one — `{"expr":"x|type string"}` is a filter expression, `|type C:\boot.ini` is not.
const TOOLS = String.raw`(?:sh|bash|dash|zsh|cmd(?:\.exe)?|powershell|pwsh|nc|ncat|curl|wget|python\d?|perl|ruby|php)`;
const READERS = String.raw`(?:cat|type|more|head|tail)`;
const FREE_TIER = String.raw`(?:whoami|ifconfig|ipconfig|netstat|tasklist|systeminfo|printenv)`;
const STRICT_TIER = String.raw`(?:hostname|uname|id|ls|dir|pwd|ps|env|set|net|reg)`;
// Query parameters whose NAME says "run this". Their value fires without a separator, but only
// with EXECUTION evidence — a tool with an argument, a recon name that is not a selector word, or
// a command followed by a separator. `?run=php`, `?command=ls&format=json` are runtime and
// listing selectors on ordinary APIs; `?cmd=whoami`, `?cmd=cat /etc/passwd` are web shells.
const EXEC_PARAM = /^(?:cmd|exec|execute|command|shell|run|system)$/i;

// Sensitive targets a traversal must reach; searched with indexOf, never a regex over the whole
// field (see traversalMatch).
const SENSITIVE_TARGETS = [
  "etc/passwd",
  "etc/shadow",
  "win.ini",
  "boot.ini",
  "web.config",
  ".env",
  ".ssh/",
  "proc/self",
  "id_rsa",
  ".git/",
];
const TRAVERSAL_WINDOW = 160; // how far before the target a `../` may sit
const SEGMENT = /\.\.[\\/]/;

interface AttackRule {
  family: string;
  re: RegExp;
}

// Rules that run over the WHOLE decoded text (any field).
const TEXT_RULES: AttackRule[] = [
  // expression: jndi (the match runs to the closing brace so two lookups are two identities), a
  // nested lookup, or a template expression carrying an operator or a call.
  {
    family: "expression",
    re: /\$\{jndi:[^}\s"'<>]{0,200}\}?|\$\{[^}]{0,40}\$\{[^}]{0,200}\}?|(?:\{\{|#\{|\$\{)[^}]{0,80}?(?:[*+\/%-]\s*\d|\w{1,40}\s*\(|T\()[^}]{0,120}\}?/i,
  },
  // sqli: structure, never a lone token; run on the copy with block comments removed.
  // The select list is part of the match, so two different union payloads are two identities.
  { family: "sqli", re: /\bunion\s+(?:all\s+)?select\b[^;"'<>]{0,200}/i },
  { family: "sqli", re: /(?:'|\d)\s{0,8}(?:or|and)\s{1,8}(?:'?\w{1,64}'?\s{0,8}=\s{0,8}'?\w{1,64}'?)/i },
  { family: "sqli", re: /\b(?:or|and)\s{1,8}(?:sleep|benchmark|pg_sleep)\s{0,8}\(\s{0,8}\d/i },
  { family: "sqli", re: /;\s{0,8}waitfor\s{1,8}delay\s{1,8}'/i },
  { family: "sqli", re: /;\s{0,8}(?:drop|insert|update|delete|exec|xp_cmdshell)\s{1,8}\w/i },
];

// Rules that run over the query string of a URL (or the whole User-Agent).
const VALUE_RULES: AttackRule[] = [
  // cmd (a): a separator + an interpreter or transfer tool WITH an argument, or a reader with a path.
  { family: "cmd", re: new RegExp(String.raw`${SEP}\s*${Q}${TOOLS}${Q}\s+${ARG}`, "i") },
  { family: "cmd", re: new RegExp(String.raw`${SEP}\s*${Q}${READERS}${Q}\s+${PATH_ARG}`, "i") },
  // cmd (b), free tier: a recon command that is not a plausible field name, after any separator.
  { family: "cmd", re: new RegExp(String.raw`${SEP}\s*${Q}${FREE_TIER}${Q}${TAIL}`, "i") },
  // cmd (b), strict tier: bare after every separator but a bare pipe …
  { family: "cmd", re: new RegExp(String.raw`${STRICT_SEP}\s*${Q}${STRICT_TIER}${Q}${TAIL}`, "i") },
  // … and after a bare pipe only with a flag or an absolute path (`fields=name|id` is filter syntax).
  { family: "cmd", re: new RegExp(String.raw`\|\s*${Q}${STRICT_TIER}${Q}\s+(?:-|\/)\S`, "i") },
];

// cmd (c): the value of an exec-named parameter, with execution evidence (see EXEC_PARAM).
const EXEC_VALUE = new RegExp(
  String.raw`^\s*(?:${Q}${TOOLS}${Q}\s+${ARG}|${Q}${READERS}${Q}\s+${PATH_ARG}|${Q}${FREE_TIER}${Q}${TAIL}|${Q}${STRICT_TIER}${Q}\s+(?:-|\/)\S|${Q}(?:${TOOLS}|${READERS}|${STRICT_TIER})${Q}\s*${SEP})`,
  "i",
);

// Block comments removed by a scan, whatever they contain and however long: `UNION/*a*b*/SELECT`
// is the oldest whitespace bypass there is, and a regex with a bounded body is a bypass with a
// length. An unterminated comment is left in place.
function stripBlockComments(text: string): string {
  let out = "";
  let i = 0;
  for (;;) {
    const open = text.indexOf("/*", i);
    if (open < 0) return out + text.slice(i);
    const close = text.indexOf("*/", open + 2);
    if (close < 0) return out + text.slice(i);
    out += text.slice(i, open) + " ";
    i = close + 2;
  }
}

// traversal: a `../` (or `..\`) segment within TRAVERSAL_WINDOW characters BEFORE a sensitive
// target. A linear scan — indexOf for each target, one bounded window test per hit — because the
// regex form (`(?:\.\.[\\/])+` then a lazy window then the alternation) backtracked for seconds on
// `../` repeated to the field bound.
function traversalMatch(text: string): string | null {
  const lower = text.toLowerCase();
  for (const target of SENSITIVE_TARGETS) {
    let at = lower.indexOf(target);
    while (at >= 0) {
      const from = Math.max(0, at - TRAVERSAL_WINDOW);
      const window = text.slice(from, at);
      const seg = SEGMENT.exec(window);
      if (seg) return text.slice(from + seg.index, at + target.length);
      at = lower.indexOf(target, at + 1);
    }
  }
  return null;
}

// The query of a decoded URL as (name, value) pairs; a URL with no query has none.
function queryPairs(url: string): Array<{ name: string; value: string }> {
  const q = url.indexOf("?");
  if (q < 0) return [];
  return url
    .slice(q + 1)
    .split("&")
    .filter(Boolean)
    .map((part) => {
      const eq = part.indexOf("=");
      return eq < 0 ? { name: part, value: "" } : { name: part.slice(0, eq), value: part.slice(eq + 1) };
    });
}

/**
 * The attack families a decoded field carries, with each match's identity form and display form,
 * or null. One match per family (the first). `isUrl` says the field is a request target or a
 * Referer: the command rules run over its query string only (a `;` in the path is matrix syntax
 * and never scanned), and an exec-named parameter is judged on its own value. A User-Agent is
 * scanned whole.
 */
export function webAttackSignal(text: string, isUrl = true): WebAttackSignal | null {
  if (!text) return null;
  const matches: AttackMatch[] = [];
  const seen = new Set<string>();
  const push = (family: string, raw: string): void => {
    seen.add(family);
    const match = raw.slice(0, MATCH_MAX);
    matches.push({ family, match, excerpt: escapeControlChars(match).slice(0, EXCERPT_MAX) });
  };
  const traversal = traversalMatch(text);
  if (traversal) push("traversal", traversal);
  const sql = stripBlockComments(text);
  for (const rule of TEXT_RULES) {
    if (seen.has(rule.family)) continue;
    const m = rule.re.exec(rule.family === "sqli" ? sql : text);
    if (m) push(rule.family, m[0]);
  }
  // The command rules run over the QUERY of a URL (the path's `;` is matrix syntax) as one string —
  // not per `&`-split value, because `&&` is itself a separator — and over the whole User-Agent.
  const q = text.indexOf("?");
  const scope = isUrl ? (q < 0 ? "" : text.slice(q + 1)) : text;
  if (scope) {
    for (const rule of VALUE_RULES) {
      const m = rule.re.exec(scope);
      if (m) {
        push("cmd", m[0]);
        break;
      }
    }
  }
  if (isUrl && !seen.has("cmd")) {
    for (const { name, value } of queryPairs(text)) {
      if (!EXEC_PARAM.test(name)) continue;
      const m = EXEC_VALUE.exec(value);
      if (m) {
        push("cmd", m[0].trim());
        break;
      }
    }
  }
  if (!matches.length) return null;
  matches.sort((a, b) => (a.family < b.family ? -1 : a.family > b.family ? 1 : 0));
  return { families: matches.map((x) => x.family), matches };
}

// ───────────── Whole-request inspection (what the importer calls) ─────────────

/** How many distinct attack payloads one path (one base aggregation key) may keep as their own rows. */
export const MAX_ATTACK_VARIANTS = 64;
const DIGEST_HEX = 16; // 64 bits, the aggKey.ts convention

export interface RequestFields {
  target: string;
  referer: string;
  ua: string;
}

export interface RequestInspection {
  /** Families with the firing field suffixed (`cmd`, `expression@ua`, `oversized@referer`), sorted. */
  families: string[];
  /** The families as displayed: an oversized entry carries its true length and "not inspected". */
  labels: string[];
  /** Display slots, one per firing field: `";cat /etc/passwd"` or `ua:"${jndi:ldap://x"`. */
  slots: string[];
  /** 16 hex of a digest over every full match with its field and family — the identity of the evidence. */
  digest: string;
}

const FIELD_ORDER: Array<keyof RequestFields> = ["target", "referer", "ua"];

/**
 * Clip, decode and scan the three attacker-controlled fields of one request line. A field past the
 * bound is NOT decoded or scanned — it fires `oversized@<field>` on its own, so the analyst is told
 * exactly what was not inspected. The target and the Referer are URLs and are decoded; the
 * User-Agent is not URL-encoded and is scanned raw. `fields` is what every later step of the
 * importer must use — the bound is applied here, once, before host, IOC, description or key.
 */
export function inspectRequestFields(raw: RequestFields): {
  inspection: RequestInspection | null;
  fields: RequestFields;
  /** The decoded target and Referer (the clipped text when nothing was encoded) — for the spill rules. */
  decodedTarget: string;
  decodedReferer: string;
} {
  const fields: RequestFields = { target: raw.target, referer: raw.referer, ua: raw.ua };
  const families: string[] = [];
  const labels: string[] = [];
  const slots: string[] = [];
  const identity: string[] = [];
  let decodedTarget = raw.target;
  let decodedReferer = raw.referer;
  for (const field of FIELD_ORDER) {
    const clipped = clipField(raw[field]);
    fields[field] = clipped.text;
    const suffix = field === "target" ? "" : `@${field}`;
    if (clipped.oversized !== null) {
      // Named with its field always, and keyed on a length BUCKET so a probe repeated at slightly
      // different lengths is one row, not one row per byte count.
      families.push(`oversized@${field}`);
      labels.push(`oversized@${field} (${clipped.oversized} chars, not inspected)`);
      identity.push(`oversized@${field}:${Math.ceil(clipped.oversized / MAX_FIELD)}`);
      if (field === "target") decodedTarget = clipped.text;
      if (field === "referer") decodedReferer = clipped.text;
      continue;
    }
    const scanned = field === "ua" ? clipped.text : decodeRequestTarget(clipped.text).decoded;
    if (field === "target") decodedTarget = scanned;
    if (field === "referer") decodedReferer = scanned;
    const signal = webAttackSignal(scanned, field !== "ua");
    if (!signal) continue;
    for (const m of signal.matches) {
      families.push(`${m.family}${suffix}`);
      labels.push(`${m.family}${suffix}`);
      identity.push(`${m.family}${suffix}:${m.match.length}:${m.match}`);
    }
    const label = field === "target" ? "" : `${field}:`;
    slots.push(`${label}"${signal.matches.map((m) => m.excerpt).join(" ")}"`);
  }
  if (!families.length) return { inspection: null, fields, decodedTarget, decodedReferer };
  const order = families
    .map((f, i) => [f, labels[i]] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const digest = createHash("sha256").update(identity.join(" ")).digest("hex").slice(0, DIGEST_HEX);
  return {
    inspection: { families: order.map((x) => x[0]), labels: order.map((x) => x[1]), slots, digest },
    fields,
    decodedTarget,
    decodedReferer,
  };
}
