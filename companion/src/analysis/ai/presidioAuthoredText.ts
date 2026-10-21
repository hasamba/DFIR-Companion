import type { CustomEntity } from "../anonymize.js";

/**
 * Presidio skips text the synthesis model wrote (summary, attacker path, finding titles and
 * descriptions), and still scans everything else in the prompt — events and analyst notes.
 *
 * WHY. A synthesis answer becomes text in the NEXT prompt: the summary rides in every later synthesis
 * prompt, and the 2nd-opinion referee prompt quotes both models' findings. The gate only sees a prompt
 * when it is about to be sent, so each pass surfaced a new batch of values that did not exist when the
 * analyst cleared the last one — the "cleared it, ran again, stopped again" loop. What Presidio finds
 * in model prose is a tool name, a malware family or an ATT&CK id tagged PERSON (#1799), never a real
 * name the model learned: the model only ever sees masked text, and every value it saw passed the gate
 * in the prompt that carried it.
 *
 * HOW. Decided per value, not by cutting text out of the prompt: the referee prompt clips a finding
 * description at 240 characters and collapses its whitespace, so the AI text is not in the prompt
 * word for word. A value is skipped only when EVERY occurrence of it in the prompt sits inside text
 * the model wrote — the characters around the occurrence agree with a recorded AI string. One
 * occurrence anywhere else (an event, an analyst note, a scaffold line) and the value is held as before.
 *
 * EVENTS ARE NEVER AI TEXT. A recorded string that an event's description contains, or that
 * contains an event's description, is not used at all: the two texts cannot be told apart in a
 * prompt, so the value is held.
 */

/** Recorded AI strings shorter than this carry too little context to tell apart from other text. */
export const AUTHORED_MIN_CHARS = 8;
/** Longer strings are cut before they are recorded; agreement only needs the text near a value. */
export const AUTHORED_MAX_CHARS = 4000;
/** Characters of agreement around an occurrence, at least, for it to count as AI-written. */
const MIN_CONTEXT = 8;
/** A whole short AI string — a finding title — counts with fewer, where the prompt frames it. */
const MIN_WHOLE_CONTEXT = 4;
// How the prompt builders frame AI text: quoted, inside or after a bracketed tag ("[F1] (severity:
// High) ", the referee's "[b_only:…]" id), after a label ("MODEL A summary: ") or after a dash (" — ").
const FRAMED_BEFORE = /(?:["“'[]|[\])] |: |— )$/;
const FRAMED_AFTER = /^(?:["”'\]]|$| — | \()/;
// The referee prompt cuts a long description and marks the cut.
const CLIP_MARK = "…";
/**
 * A cut with no mark (the referee's 240-character description) counts only after this many matching
 * characters. Shorter, and a line that merely starts like AI text — an event — would pass.
 */
const UNMARKED_CLIP_MIN = 200;

/** Whitespace collapsed and trimmed — the form the prompt builders print AI text in. */
export function normalizeAuthored(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/** The synthesis-answer fields the model wrote. Nothing else: an extraction answer becomes events. */
export function authoredStrings(delta: {
  summary?: string;
  attackerPath?: string;
  findings?: readonly { title?: string; description?: string }[];
}): string[] {
  const raw = [
    delta.summary,
    delta.attackerPath,
    ...(delta.findings ?? []).flatMap((f) => [f.title, f.description]),
  ];
  const out = new Set<string>();
  for (const s of raw) {
    if (typeof s !== "string") continue;
    const n = normalizeAuthored(s).slice(0, AUTHORED_MAX_CHARS);
    if (n.length >= AUTHORED_MIN_CHARS) out.add(n);
  }
  return [...out];
}

/** What the gate needs to tell AI text apart: the recorded strings and the call's restore. */
export interface AuthoredText {
  /** Recorded AI strings, as recorded (real values, whitespace collapsed). */
  corpus: readonly string[];
  /** The call's anonymizer restore: masked prompt text back to real values, like the corpus. */
  restore: (masked: string) => string;
  /** The case's event descriptions (real values). A recorded string that overlaps one is not used. */
  events?: readonly string[];
}

const isWordChar = (ch: string | undefined): boolean => ch !== undefined && /[\p{L}\p{N}_]/u.test(ch);

/** Start offsets of `v` in `line` that stand on their own — "ann" is not an occurrence in "announce". */
function boundedOccurrences(line: string, v: string): number[] {
  const out: number[] = [];
  const guardLeft = isWordChar(v[0]);
  const guardRight = isWordChar(v[v.length - 1]);
  for (let i = line.indexOf(v); i >= 0; i = line.indexOf(v, i + 1)) {
    if (guardLeft && isWordChar(line[i - 1])) continue;
    if (guardRight && isWordChar(line[i + v.length])) continue;
    out.push(i);
  }
  return out;
}

/**
 * Is the occurrence at `line[s]` inside a copy of a recorded AI string?
 *
 * AI text sits in a prompt as one unbroken piece, framed by prompt structure: a label, a quote, a
 * bracketed tag or a dash before it; a quote, a dash, a bracket or the line end after it. So the
 * line must agree with the AI string all the way back to that string's start, with a frame before
 * it, and all the way forward to the string's end with a frame after it — or to a clip. An event
 * that shares a phrase with AI prose (" on the domain controller") stops agreeing next to the
 * value; one that starts like AI text and goes on ("Investigate Jane Doe after a login") has no
 * frame after the string.
 */
function occurrenceAuthored(line: string, s: number, v: string, corpus: readonly string[]): boolean {
  const e = s + v.length;
  for (const c of corpus) {
    for (let p = c.indexOf(v); p >= 0; p = c.indexOf(v, p + 1)) {
      if (s < p || line.slice(s - p, s) !== c.slice(0, p)) continue; // back to the AI string's start
      const q = p + v.length;
      let right = 0;
      while (e + right < line.length && q + right < c.length && line[e + right] === c[q + right]) right++;
      const end = e + right;
      const matched = p + right;
      if (!FRAMED_BEFORE.test(line.slice(0, s - p))) continue;
      const framedEnd = q + right === c.length && FRAMED_AFTER.test(line.slice(end));
      const clipped = line[end] === CLIP_MARK || (end === line.length && matched >= UNMARKED_CLIP_MIN);
      if (!framedEnd && !clipped) continue;
      if (matched >= MIN_CONTEXT) return true;
      if (framedEnd && matched >= MIN_WHOLE_CONTEXT) return true;
    }
  }
  return false;
}

/** True only when the value occurs in the prompt and every occurrence is inside AI-written text. */
export function onlyInAuthoredText(maskedText: string, value: string, authored: AuthoredText): boolean {
  const v = normalizeAuthored(value).toLowerCase();
  if (!v) return false;
  const events = (authored.events ?? [])
    .map((t) => normalizeAuthored(t).toLowerCase())
    .filter((t) => t.includes(v));
  const corpus = authored.corpus
    .map((c) => c.toLowerCase())
    .filter((c) => c.includes(v) && !events.some((t) => t.includes(c) || c.includes(t)));
  if (corpus.length === 0) return false;
  let seen = false;
  for (const masked of maskedText.split("\n")) {
    // Normalized BEFORE the check: "Jane   Doe" in an event is an occurrence of "Jane Doe".
    if (!normalizeAuthored(masked).toLowerCase().includes(v)) continue;
    const line = normalizeAuthored(authored.restore(masked)).toLowerCase();
    for (const s of boundedOccurrences(line, v)) {
      if (!occurrenceAuthored(line, s, v, corpus)) return false;
      seen = true;
    }
  }
  return seen;
}

/** Split fresh Presidio values into those still held and those found only in AI-written text. */
export function splitAuthored(
  fresh: readonly CustomEntity[],
  maskedText: string,
  authored: AuthoredText | undefined,
): { held: CustomEntity[]; skipped: CustomEntity[] } {
  if (!authored || authored.corpus.length === 0) return { held: [...fresh], skipped: [] };
  const held: CustomEntity[] = [];
  const skipped: CustomEntity[] = [];
  for (const e of fresh) (onlyInAuthoredText(maskedText, e.value, authored) ? skipped : held).push(e);
  return { held, skipped };
}
