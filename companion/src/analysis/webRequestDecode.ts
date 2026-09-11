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
    const s = query === null ? null : decodeOnce(query, true);
    malformed = malformed || p.malformed || (s?.malformed ?? false);
    if (!p.changed && !(s?.changed ?? false)) break;
    path = p.out;
    if (s) query = s.out;
    passes++;
  }
  return { original: text, decoded: query === null ? path : `${path}?${query}`, passes, malformed };
}

// ───────────── Attack shapes ─────────────
// Every regex is linear: no nested quantifiers over one class, no unbounded `.*` between anchors.

const BT = "`";
const SEP = String.raw`(?:;|\|\||&&|\||` + BT + String.raw`|\$\()`; // shell separators
const STRICT_SEP = String.raw`(?:;|\|\||&&|` + BT + String.raw`|\$\()`; // every separator but a bare pipe
const ARG = String.raw`[^\s;|&"'<>` + BT + String.raw`]{1,200}`; // one argument token, bounded
const TAIL = String.raw`(?=$|[\s;|&"'` + BT + String.raw`)\x00-\x1f])`; // what may follow a direct command — never `=`

const TOOLS = String.raw`(?:sh|bash|dash|zsh|cmd(?:\.exe)?|powershell|pwsh|nc|ncat|curl|wget|python\d?|perl|ruby|php|cat|type)`;
const FREE_TIER = String.raw`(?:whoami|ifconfig|ipconfig|netstat|tasklist|systeminfo|printenv)`;
const STRICT_TIER = String.raw`(?:hostname|uname|id|ls|dir|pwd|ps|env|set|net|reg)`;

interface AttackRule {
  family: string;
  re: RegExp;
}

const ATTACK_RULES: AttackRule[] = [
  // traversal: one or more `../` (or `..\`) segments FOLLOWED BY a sensitive target.
  {
    family: "traversal",
    re: /(?:\.\.[\\/])+(?:[^\s"'<>]{0,120}?)(?:etc\/passwd|etc\/shadow|win\.ini|boot\.ini|web\.config|\.env\b|\.ssh\/|proc\/self|id_rsa|\.git\/)/i,
  },
  // cmd (a): a separator + an interpreter or transfer tool WITH an argument.
  { family: "cmd", re: new RegExp(String.raw`${SEP}\s*${TOOLS}\s+${ARG}`, "i") },
  // cmd (b), free tier: a recon command that is not a plausible field name, after any separator.
  { family: "cmd", re: new RegExp(String.raw`${SEP}\s*${FREE_TIER}${TAIL}`, "i") },
  // cmd (b), strict tier: bare after every separator but a bare pipe …
  { family: "cmd", re: new RegExp(String.raw`${STRICT_SEP}\s*${STRICT_TIER}${TAIL}`, "i") },
  // … and after a bare pipe only with a flag or an absolute path (`fields=name|id` is filter syntax).
  { family: "cmd", re: new RegExp(String.raw`\|\s*${STRICT_TIER}\s+(?:-|\/)\S`, "i") },
  // expression: jndi (the match runs to the closing brace so two lookups are two identities), a
  // nested lookup, or a template expression carrying an operator or a call.
  {
    family: "expression",
    re: /\$\{jndi:[^}\s"'<>]{0,200}\}?|\$\{[^}]{0,40}\$\{[^}]{0,200}\}?|(?:\{\{|#\{|\$\{)[^}]{0,80}?(?:[*+\/%-]\s*\d|\w+\s*\(|T\()[^}]{0,120}\}?/i,
  },
  // sqli: structure, never a lone token.
  // The select list is part of the match, so two different union payloads are two identities.
  { family: "sqli", re: /\bunion\s+(?:all\s+)?select\b[^;"'<>]{0,200}/i },
  { family: "sqli", re: /(?:'|\d)\s*(?:or|and)\s+(?:'?[\w]+'?\s*=\s*'?[\w]+'?|\d+\s*=\s*\d+)/i },
  { family: "sqli", re: /\b(?:or|and)\s+(?:sleep|benchmark|pg_sleep)\s*\(\s*\d/i },
  { family: "sqli", re: /;\s*waitfor\s+delay\s+'/i },
  { family: "sqli", re: /;\s*(?:drop|insert|update|delete|exec|xp_cmdshell)\s+\w/i },
];

/**
 * The attack families a decoded request field carries, with each match's identity form and display
 * form, or null. One match per family (the first).
 */
export function webAttackSignal(text: string): WebAttackSignal | null {
  if (!text) return null;
  const matches: AttackMatch[] = [];
  const seen = new Set<string>();
  for (const rule of ATTACK_RULES) {
    if (seen.has(rule.family)) continue;
    const m = rule.re.exec(text);
    if (!m) continue;
    seen.add(rule.family);
    const match = m[0].slice(0, MATCH_MAX);
    matches.push({ family: rule.family, match, excerpt: escapeControlChars(match).slice(0, EXCERPT_MAX) });
  }
  return matches.length ? { families: matches.map((x) => x.family), matches } : null;
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
    const signal = webAttackSignal(scanned);
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
