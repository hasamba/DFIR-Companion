import { findCustomSpans, type CompiledCustom } from "./anonCustomSpans.js";
import { SECRET_PLACEHOLDER, redactSecretText } from "./anonSecrets.js";

// The secret pass of the anonymizer, made aware of custom entities (#2952).
//
// Secrets are redacted one way BEFORE custom entities are matched, so a secret that is also a
// custom value never becomes a reversible token (#2950). But after redaction a custom value that
// CONTAINS a secret no longer has its spelling ("srv01:confidential?password=" + placeholder), and
// the custom pass drops a match that touches the placeholder — so the rest of the custom value went
// to the AI in clear. Here every custom match is found on the text BEFORE redaction; one that
// overlaps or touches a redacted secret is hidden together with it as ONE one-way placeholder.
// Nothing about that occurrence is restorable: the analyst gets the placeholder back, and no part
// of the custom value lands in the reversible token table. A custom match wholly inside a secret is
// already hidden and changes nothing.
//
// redactSecretText() returns only a string, so secret positions are recovered by lining its output
// up against its input. That is sound because every redaction pass replaces intervals of the text
// with the placeholder (a bare JSON number gets it in quotes). Where a stretch of text repeats near
// a secret the line-up is ambiguous; the LOOSE bounds then cover every placement, so the result can
// over-redact, never under-redact. If no line-up exists at all (not reachable by construction) the
// whole changed window is treated as one secret: fail closed.

export interface Interval {
  start: number;
  end: number;
}

/** One redacted secret in the clear text's coordinates. */
export interface SecretSpan {
  exact: Interval; // one valid placement — rebuilding with it reproduces the redactor's output
  loose: Interval; // covers every valid placement
  sure: Interval; // inside every valid placement (may be empty)
  form: string; // what the redactor wrote: the sentinel, or the sentinel in quotes
}

/** The redactor's output with every placeholder as `sentinel`. Pure. */
export function redactToSentinel(text: string, sentinel: string): string {
  return redactSecretText(text).split(SECRET_PLACEHOLDER).join(sentinel);
}

/**
 * Redact secrets one way; a custom match that overlaps or touches a secret is redacted with it,
 * as is any IPv6 address the merged region would cut. `addresses` is only called when needed.
 */
export function redactSecretsWithCustom(
  text: string,
  compiled: CompiledCustom,
  sentinel: string,
  addresses: () => Interval[],
): string {
  const redacted = redactToSentinel(text, sentinel);
  if (!redacted.includes(sentinel)) return redacted;
  const custom = findCustomSpans(text, compiled);
  if (custom.length === 0) return redacted;
  return coverCustomSecrets(text, redacted, sentinel, custom, addresses());
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Where each secret of `redacted` sits in `text`, or null when the two cannot be lined up. */
export function locateSecrets(text: string, redacted: string, sentinel: string): SecretSpan[] | null {
  const marker = new RegExp(`"${escapeRe(sentinel)}"|${escapeRe(sentinel)}`, "g");
  const forms = redacted.match(marker) ?? [];
  const segs = redacted.split(marker);
  const early = earliest(text, segs);
  const late = early && latest(text, segs, early);
  if (!early || !late) return null;
  return forms.map((form, k) => {
    const after = segs[k].length;
    const from = early[k] + after;
    return {
      exact: { start: from, end: early[k + 1] },
      loose: { start: from, end: late[k + 1] },
      sure: { start: late[k] + after, end: Math.max(late[k] + after, early[k + 1]) },
      form,
    };
  });
}

// Leftmost start of every segment; each secret between two segments is at least one character.
function earliest(text: string, segs: readonly string[]): number[] | null {
  const n = segs.length - 1;
  if (!text.startsWith(segs[0])) return null;
  const out = [0];
  let cur = segs[0].length;
  for (let i = 1; i < n; i++) {
    const at = text.indexOf(segs[i], cur + 1);
    if (at < 0) return null;
    out.push(at);
    cur = at + segs[i].length;
  }
  const last = text.length - segs[n].length;
  if (last < cur + 1 || !text.endsWith(segs[n])) return null;
  out.push(last);
  return out;
}

// Rightmost start of every segment, consistent with the leftmost ones.
function latest(text: string, segs: readonly string[], early: readonly number[]): number[] | null {
  const n = segs.length - 1;
  const out = new Array<number>(n + 1);
  out[0] = 0;
  out[n] = early[n];
  let cur = early[n];
  for (let i = n - 1; i >= 1; i--) {
    const from = cur - 1 - segs[i].length;
    const at = from < 0 ? -1 : text.lastIndexOf(segs[i], from);
    if (at < early[i]) return null;
    out[i] = at;
    cur = at;
  }
  return out;
}

// Not reachable by construction: everything between the common prefix and suffix is one secret.
function changedWindow(text: string, redacted: string): SecretSpan {
  const max = Math.min(text.length, redacted.length);
  let p = 0;
  while (p < max && text[p] === redacted[p]) p++;
  let q = 0;
  while (q < max - p && text[text.length - 1 - q] === redacted[redacted.length - 1 - q]) q++;
  const window = { start: p, end: text.length - q };
  return { exact: window, loose: window, sure: window, form: "" };
}

type Piece = Interval & { secret?: SecretSpan; custom?: boolean };

/**
 * Rebuild the redacted text with every custom match that overlaps or touches a secret hidden
 * together with it. Returns `redacted` itself when no custom match touches a secret.
 */
export function coverCustomSecrets(
  text: string,
  redacted: string,
  sentinel: string,
  custom: readonly Interval[],
  addresses: readonly Interval[],
): string {
  const located = locateSecrets(text, redacted, sentinel);
  const secrets = located ?? [changedWindow(text, redacted)];
  const inside = (c: Interval) => {
    const s = secrets[lastStartingBy(secrets, c.start)];
    return s !== undefined && s.sure.start <= c.start && c.end <= s.sure.end;
  };
  const pieces: Piece[] = [
    ...secrets.map((s) => ({ ...s.loose, secret: s })),
    ...custom.filter((c) => !inside(c)).map((c) => ({ start: c.start, end: c.end, custom: true })),
    ...addresses.map((a) => ({ start: a.start, end: a.end })),
  ].sort((a, b) => a.start - b.start || b.end - a.end);
  const groups = groupTouching(pieces);
  const tainted = (g: readonly Piece[]) => g.some((p) => p.custom) && g.some((p) => p.secret);
  if (!groups.some(tainted)) return redacted;
  let out = "";
  let at = 0;
  for (const g of groups) {
    if (tainted(g)) {
      const start = Math.min(...g.map((p) => p.start));
      out += text.slice(at, start) + sentinel;
      at = Math.max(...g.map((p) => p.end));
      continue;
    }
    for (const p of g) {
      if (!p.secret) continue;
      out += text.slice(at, p.secret.exact.start) + p.secret.form;
      at = p.secret.exact.end;
    }
  }
  return out + text.slice(at);
}

// Index of the last secret whose sure interval starts at or before `at` (-1 if none). Sure intervals
// are in text order and never overlap, so only that one can contain a span starting at `at`.
function lastStartingBy(secrets: readonly SecretSpan[], at: number): number {
  let lo = 0;
  let hi = secrets.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (secrets[mid].sure.start <= at) lo = mid + 1;
    else hi = mid - 1;
  }
  return hi;
}

// Pieces that overlap or touch, transitively. Touching counts: the custom pass drops a match next
// to a placeholder, so a custom value left beside a hidden region would go out in clear.
function groupTouching(pieces: readonly Piece[]): Piece[][] {
  const groups: Piece[][] = [];
  let end = -1;
  for (const p of pieces) {
    if (groups.length === 0 || p.start > end) groups.push([]);
    groups[groups.length - 1].push(p);
    end = Math.max(end, p.end);
  }
  return groups;
}
