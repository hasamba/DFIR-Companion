import type { AnonPair, AnonPolicy, Anonymizer } from "../anonymize.js";
import { SECRET_PLACEHOLDER } from "../anonymize.js";
import { possibleLeaks, type PreviewWarning } from "./previewLeaks.js";

/**
 * The GitHub-style diff "Preview what the AI will see" draws (#2531): which clear value became which
 * token, where, and what on the masked side still looks unmasked.
 *
 * The value→token pairs are the real anonymizer's own map (`Anonymizer.pairs()`, the map restore()
 * reads) — never re-guessed. This module only lines them up against the two texts. Masking is a pure
 * substitution, so the walk is strict: the text between two replacements must be identical on both
 * sides, and a token's value must sit exactly at the cursor (case-insensitively — the anonymizer keys
 * values lower-case — or in its JSON-escaped form for the decision-model panes). Anything else is NOT
 * guessed: the walk retries line by line, marking a line it still cannot line up as changed with no
 * inline marks, and gives up ("none") when even that is impossible. One pass, linear in the text.
 *
 * The one span without a pair is a one-way secret: nothing maps `[REDACTED_SECRET]` back, so its clear
 * extent runs to the next unchanged text that is followed by the next token's own value (or closes the
 * text), and the rest of the walk must still match exactly. Two secrets with only plain text between
 * them cannot be split provably, so that walk gives up.
 *
 * Built only inside the preview; the result lives in the preview response and nowhere else.
 */
export interface PreviewMark {
  /** [start, end) in the clear text. */
  readonly c: readonly [number, number];
  /** [start, end) in the masked text. */
  readonly m: readonly [number, number];
  /** Index into `pairs`; -1 for a one-way secret (no pair). */
  readonly pair: number;
}

export type { PreviewWarning } from "./previewLeaks.js";

export interface PreviewDiff {
  /** "text": lined up over the whole text; "lines": line by line; "none": could not be lined up. */
  readonly mode: "text" | "lines" | "none";
  readonly pairs: readonly AnonPair[];
  readonly marks: readonly PreviewMark[];
  /** Masked line numbers (0-based) that changed but could not be lined up value by value. */
  readonly unalignedLines: readonly number[];
  readonly warnings: readonly PreviewWarning[];
  /** Replacements by token category ("SECRET" for one-way secrets). */
  readonly counts: Readonly<Record<string, number>>;
  /** Masked lines holding at least one replacement or an unaligned change. */
  readonly changedLines: number;
}

const TOKEN_SHAPE = /ANON_[A-Z]+_\d+|\[REDACTED_SECRET\]/g;

export function previewDiff(
  clear: string,
  masked: string,
  anon: Pick<Anonymizer, "pairs">,
  policy: Pick<AnonPolicy, "maskPublicIps">,
): PreviewDiff {
  const pairs = anon.pairs().filter((p) => masked.includes(p.token));
  const byToken = new Map(pairs.map((p, i) => [p.token, i]));
  const warnings = possibleLeaks(masked, policy);
  const whole = walk(clear, masked, byToken, pairs, 0, 0);
  if (whole) return finish("text", pairs, whole, [], warnings, masked);
  const byLine = walkLines(clear, masked, byToken, pairs);
  if (byLine) return finish("lines", pairs, byLine.marks, byLine.unaligned, warnings, masked);
  return finish("none", pairs, [], [], warnings, masked);
}

/** Line by line, when both texts have the same number of lines (always so for the Jev JSON panes). */
function walkLines(
  clear: string,
  masked: string,
  byToken: ReadonlyMap<string, number>,
  pairs: readonly AnonPair[],
): { marks: PreviewMark[]; unaligned: number[] } | null {
  const cl = clear.split("\n");
  const ml = masked.split("\n");
  if (cl.length !== ml.length) return null;
  const marks: PreviewMark[] = [];
  const unaligned: number[] = [];
  let cBase = 0;
  let mBase = 0;
  for (let i = 0; i < ml.length; i++) {
    if (cl[i] !== ml[i]) {
      const found = walk(cl[i], ml[i], byToken, pairs, cBase, mBase);
      if (found) marks.push(...found);
      else unaligned.push(i);
    }
    cBase += cl[i].length + 1;
    mBase += ml[i].length + 1;
  }
  return { marks, unaligned };
}

/** Length of `value` at clear[at], as-is, case-insensitively or JSON-escaped; -1 when it is not there. */
function valueAt(clear: string, at: number, value: string): number {
  const json = JSON.stringify(value).slice(1, -1);
  for (const v of json === value ? [value] : [value, json]) {
    const seg = clear.slice(at, at + v.length);
    if (seg === v || seg.toLowerCase() === v.toLowerCase()) return v.length;
  }
  return -1;
}

interface Cursor {
  ci: number;
  mi: number;
  /** A secret placeholder whose clear extent is still open: its masked [start, end). */
  secret: [number, number] | null;
}

/** The strict walk over one clear/masked pair. Offsets are shifted by the bases. null = not lined up. */
function walk(
  clear: string,
  masked: string,
  byToken: ReadonlyMap<string, number>,
  pairs: readonly AnonPair[],
  cBase: number,
  mBase: number,
): PreviewMark[] | null {
  const marks: PreviewMark[] = [];
  const cur: Cursor = { ci: 0, mi: 0, secret: null };
  const re = new RegExp(TOKEN_SHAPE.source, "g");
  for (let hit = re.exec(masked); hit; hit = re.exec(masked)) {
    const at = hit.index;
    const tok = hit[0];
    const pair = byToken.get(tok);
    const isSecret = tok === SECRET_PLACEHOLDER;
    if (pair === undefined && !isSecret) continue; // not minted here: plain text, part of the next literal
    const literal = masked.slice(cur.mi, at);
    // Two secrets in a row: nothing proves where the first one ends (a private-key header alone is a
    // secret too), so this walk gives up rather than split them by guesswork.
    if (isSecret && cur.secret) return null;
    // An open secret ends where this literal is followed by this hit's own value.
    const follows = (j: number): boolean =>
      valueAt(clear, j + literal.length, pairs[pair!].value) >= 0 ||
      clear.startsWith(tok, j + literal.length);
    if (!closeSecret(clear, literal, cur, marks, cBase, mBase, follows)) return null;
    if (!clear.startsWith(literal, cur.ci)) return null;
    cur.ci += literal.length;
    cur.mi = at;
    // The same text already in the clear text is plain text, not a replacement.
    const asValue = isSecret ? -1 : valueAt(clear, cur.ci, pairs[pair!].value);
    if (asValue < 0 && clear.startsWith(tok, cur.ci)) continue;
    if (isSecret) {
      cur.secret = [at, at + tok.length];
    } else {
      if (asValue < 0) return null; // never guess where a token's value was
      marks.push({
        c: [cBase + cur.ci, cBase + cur.ci + asValue],
        m: [mBase + at, mBase + at + tok.length],
        pair: pair!,
      });
      cur.ci += asValue;
    }
    cur.mi = at + tok.length;
  }
  const rest = masked.slice(cur.mi);
  if (!closeSecret(clear, rest, cur, marks, cBase, mBase, null)) return null;
  return clear.slice(cur.ci) === rest ? marks : null;
}

// How far past its start a secret's clear extent is searched for. The longest thing the secret pass
// redacts is a private-key block, which it bounds at about 8 KB; this keeps the search linear.
const SECRET_SEARCH_MAX = 16_384;

/**
 * Ends an open secret at the next unchanged text: the first place the literal appears AND is followed
 * by the next hit's own value (`follows`), so a newline inside a private key is not taken for the
 * newline after it. At the end of the text (`follows` null) the remaining text must close it exactly.
 */
function closeSecret(
  clear: string,
  literal: string,
  cur: Cursor,
  marks: PreviewMark[],
  cBase: number,
  mBase: number,
  follows: ((j: number) => boolean) | null,
): boolean {
  if (!cur.secret) return true;
  let end: number;
  if (!follows) {
    end = clear.length - literal.length;
    if (end < cur.ci || !clear.endsWith(literal)) return false;
  } else {
    if (!literal) return false; // two replacements side by side: the secret's extent is unknown
    const limit = cur.ci + SECRET_SEARCH_MAX;
    end = clear.indexOf(literal, cur.ci);
    while (end >= 0 && end <= limit && !follows(end)) end = clear.indexOf(literal, end + 1);
    if (end < 0 || end > limit) return false;
  }
  marks.push({
    c: [cBase + cur.ci, cBase + end],
    m: [mBase + cur.secret[0], mBase + cur.secret[1]],
    pair: -1,
  });
  cur.ci = end;
  cur.secret = null;
  return true;
}

function finish(
  mode: PreviewDiff["mode"],
  pairs: readonly AnonPair[],
  marks: readonly PreviewMark[],
  unalignedLines: readonly number[],
  warnings: readonly PreviewWarning[],
  masked: string,
): PreviewDiff {
  const counts: Record<string, number> = {};
  for (const m of marks) {
    const cat = m.pair < 0 ? "SECRET" : pairs[m.pair].category;
    counts[cat] = (counts[cat] ?? 0) + 1;
  }
  const lines = new Set(unalignedLines);
  // Marks are in masked order: one forward sweep counts the line each one starts on.
  let line = 0;
  let pos = 0;
  for (const m of marks) {
    for (let nl = masked.indexOf("\n", pos); nl !== -1 && nl < m.m[0]; nl = masked.indexOf("\n", pos)) {
      line++;
      pos = nl + 1;
    }
    lines.add(line);
  }
  return { mode, pairs, marks, unalignedLines, warnings, counts, changedLines: lines.size };
}
