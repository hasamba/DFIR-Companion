import type { CustomEntity } from "../anonymize.js";
import type { Logger } from "../../logging/logger.js";
import type { AiAuthoredTextStore } from "../aiAuthoredText.js";
import type { PromptSegment } from "./aiSpan.js";

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
 * HOW. Two facts, both required. WHERE: the prompt builders mark each AI field they print (aiSpan.ts),
 * so the gate knows a span's position without reading its text. WHAT: the span's text must equal a
 * string the synthesis model wrote, recorded when it answered — or begin one, where the builder cut
 * it. A field the code wrote (a backfill finding built from an event) is marked but not recorded, so it
 * is not trusted. A value is skipped only when every occurrence of it in the prompt is inside such a
 * span. An event or an analyst note is never marked, so any occurrence there holds the value — even
 * when it repeats AI prose word for word.
 */

/** Recorded AI strings shorter than this carry too little context to tell apart from other text. */
export const AUTHORED_MIN_CHARS = 8;
/** Longer strings are cut before they are recorded; agreement only needs the text near a value. */
export const AUTHORED_MAX_CHARS = 4000;
/** A cut span must hold at least this much text to stand for the start of a recorded string. */
const CLIPPED_MIN_CHARS = 24;
const CLIP_MARK = "…";

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

/** One AI-marked span of the masked prompt, as prepareCall found it. */
export interface AuthoredSpan {
  start: number;
  end: number;
  /** The builder cut the field, so its text is the start of a recorded string. */
  clipped: boolean;
}

/** What the gate needs: where the AI fields are, what the model wrote, and the call's restore. */
export interface AuthoredText {
  /** Recorded AI strings, as recorded (real values, whitespace collapsed). */
  corpus: readonly string[];
  /** The AI-marked spans of the masked prompt. */
  spans: readonly AuthoredSpan[];
  /** The call's anonymizer restore: masked prompt text back to real values, like the corpus. */
  restore: (masked: string) => string;
}

/** The spans whose text the synthesis model is recorded as having written. */
function confirmedSpans(maskedText: string, authored: AuthoredText): AuthoredSpan[] {
  const corpus = authored.corpus.map((c) => c.toLowerCase());
  const whole = new Set(corpus);
  return authored.spans.filter((sp) => {
    const shown = normalizeAuthored(authored.restore(maskedText.slice(sp.start, sp.end))).toLowerCase();
    if (whole.has(shown)) return true;
    if (!sp.clipped) return false;
    const head = shown.endsWith(CLIP_MARK) ? shown.slice(0, -CLIP_MARK.length).trimEnd() : shown;
    return head.length >= CLIPPED_MIN_CHARS && corpus.some((c) => c.startsWith(head));
  });
}

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const WORD = "[\\p{L}\\p{N}_]";

/**
 * Every occurrence of the value in the prompt: any case, any run of whitespace between its words
 * ("Jane   Doe" is "Jane Doe"), and standing on its own — "Ann" does not occur in "Announce".
 */
function occurrences(text: string, value: string): { start: number; end: number }[] {
  const words = normalizeAuthored(value).split(" ").map(escapeRegExp);
  const left = new RegExp(`^${WORD}`, "u").test(words[0] ?? "") ? `(?<!${WORD})` : "";
  const right = new RegExp(`${WORD}$`, "u").test(words[words.length - 1] ?? "") ? `(?!${WORD})` : "";
  const re = new RegExp(`${left}${words.join("\\s+")}${right}`, "giu");
  return [...text.matchAll(re)].map((m) => ({ start: m.index, end: m.index + m[0].length }));
}

/** True only when the value occurs in the prompt and every occurrence is inside a confirmed span. */
export function onlyInAuthoredText(maskedText: string, value: string, authored: AuthoredText): boolean {
  if (!normalizeAuthored(value)) return false;
  return onlyInSpans(maskedText, value, confirmedSpans(maskedText, authored));
}

function onlyInSpans(maskedText: string, value: string, spans: readonly AuthoredSpan[]): boolean {
  if (spans.length === 0) return false;
  const found = occurrences(maskedText, value);
  return found.length > 0 && found.every((o) => spans.some((sp) => o.start >= sp.start && o.end <= sp.end));
}

/** Split fresh Presidio values into those still held and those found only in AI-written text. */
export function splitAuthored(
  fresh: readonly CustomEntity[],
  maskedText: string,
  authored: AuthoredText | undefined,
): { held: CustomEntity[]; skipped: CustomEntity[] } {
  if (!authored || authored.corpus.length === 0 || authored.spans.length === 0)
    return { held: [...fresh], skipped: [] };
  const spans = confirmedSpans(maskedText, authored);
  const held: CustomEntity[] = [];
  const skipped: CustomEntity[] = [];
  for (const e of fresh)
    (normalizeAuthored(e.value) && onlyInSpans(maskedText, e.value, spans) ? skipped : held).push(e);
  return { held, skipped };
}

/**
 * Mask a split prompt one segment at a time, so each AI span keeps exact offsets in the masked text.
 * One anonymizer serves every segment, so a value gets the same token wherever it appears. A prompt
 * with no AI spans is one segment — masked whole, exactly as before.
 */
export function maskSegments(
  segments: readonly PromptSegment[],
  apply: (text: string) => string,
): { masked: string; spans: AuthoredSpan[] } {
  let masked = "";
  const spans: AuthoredSpan[] = [];
  for (const sg of segments) {
    const m = apply(sg.text);
    if (sg.ai) spans.push({ start: masked.length, end: masked.length + m.length, clipped: sg.clipped });
    masked += m;
  }
  return { masked, spans };
}

/** The gate's view of the AI text. Nothing to skip, or a record that cannot be read: undefined. */
export async function authoredFor(
  store: AiAuthoredTextStore | undefined,
  log: Logger,
  caseId: string,
  call: Pick<AuthoredText, "spans" | "restore">,
): Promise<AuthoredText | undefined> {
  if (!store || call.spans.length === 0) return undefined;
  try {
    const corpus = await store.load(caseId);
    return corpus.length > 0 ? { ...call, corpus } : undefined;
  } catch (err) {
    log.warn(
      `[presidio] could not read the AI-written text record — every value is held: ${(err as Error).message}`,
      {
        caseId,
      },
    );
    return undefined;
  }
}
