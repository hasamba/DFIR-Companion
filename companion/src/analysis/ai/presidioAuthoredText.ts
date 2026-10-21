import { AsyncLocalStorage } from "node:async_hooks";
import { neutralizeAnonTokens, type CustomEntity } from "../anonymize.js";
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
 * it. The record holds the answer AS THE MODEL WROTE IT, placeholders and all, and both sides are
 * compared token-neutral: every placeholder is one mark, so ANON_HOST_1 in one call matches
 * ANON_HOST_3 in the next. A real value restored into the answer is a placeholder in the record, so
 * it can never pass as the model's own word — un-mask "Jane Doe" later and the prompt shows the
 * name where the record has a placeholder, and the value is held. A field the code wrote (a backfill finding built from an event) is marked but not recorded, so it
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

/**
 * The synthesis-answer fields the model wrote. Nothing else: an extraction answer becomes events.
 * Takes the answer as parsed, before validation — it is read, never trusted.
 */
export function authoredStrings(answer: unknown): string[] {
  const a = (answer ?? {}) as { summary?: unknown; attackerPath?: unknown; findings?: unknown };
  const findings = Array.isArray(a.findings)
    ? (a.findings as { title?: unknown; description?: unknown }[])
    : [];
  const raw = [a.summary, a.attackerPath, ...findings.flatMap((f) => [f?.title, f?.description])];
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

/** What the gate needs: where the AI fields are, and what the model wrote. */
export interface AuthoredText {
  /** Recorded AI strings, as the model wrote them (placeholders kept, whitespace collapsed). */
  corpus: readonly string[];
  /** The AI-marked spans of the masked prompt. */
  spans: readonly AuthoredSpan[];
}

const TOKEN_MARK = "\u2400";

/** The form both sides are compared in: whitespace collapsed, lower case, every placeholder one mark. */
export function neutralAuthored(text: string): string {
  return neutralizeAnonTokens(normalizeAuthored(text), TOKEN_MARK).toLowerCase();
}

/** The spans whose text the synthesis model is recorded as having written. */
function confirmedSpans(maskedText: string, authored: AuthoredText): AuthoredSpan[] {
  const corpus = authored.corpus.map(neutralAuthored);
  const whole = new Set(corpus);
  return authored.spans.filter((sp) => {
    const shown = neutralAuthored(maskedText.slice(sp.start, sp.end));
    if (whole.has(shown)) return true;
    if (!sp.clipped) return false;
    const head = shown.endsWith(CLIP_MARK) ? shown.slice(0, -CLIP_MARK.length).trimEnd() : shown;
    return head.length >= CLIPPED_MIN_CHARS && corpus.some((c) => c.startsWith(head));
  });
}

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Every occurrence of the value in the prompt: any case, and any run of whitespace between its words
 * ("Jane   Doe" is "Jane Doe"). Inside other text too — "Jane Doe_ VPN", even "Ann" in "Announce".
 * Presidio's own spans are not kept, so the gate cannot know which occurrence it found; a word-boundary
 * rule would drop one Presidio may have flagged. A false hold costs one approval; a false skip leaks.
 */
function occurrences(text: string, value: string): { start: number; end: number }[] {
  const words = normalizeAuthored(value).split(" ").map(escapeRegExp);
  const re = new RegExp(words.join("\\s+"), "giu");
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

/**
 * A part of a visible value shorter than this counts only as a whole word: "Li" must not drop
 * "login". Except in a script without letter case (Chinese, Japanese, Thai…): there names run into
 * the text with no space ("王小明"), so a word boundary never stands beside the part.
 */
const VISIBLE_PART_SUBSTRING_CHARS = 3;
const CASELESS_LETTER = /\p{Lo}/u;
/**
 * What may not stand beside a short part for it to count as a word. For a part with a letter, only
 * another letter: "_" and digits end it, so "Li" counts in "Li_backup" and in "Li2026", identifiers
 * the model may build from the name. For a part of digits only, a digit too: "7" from "Unit 7" must
 * not drop every string with a year in it.
 */
const LETTER = "\\p{L}";
const LETTER_OR_DIGIT = "[\\p{L}\\p{N}]";
const shortPart = (p: string): RegExp => {
  const edge = /\p{L}/u.test(p) ? LETTER : LETTER_OR_DIGIT;
  return new RegExp(`(?<!${edge})${escapeRegExp(p)}(?!${edge})`, "iu");
};

/**
 * The strings that hold no value the analyst left visible ("Leave visible", the suppressed list), and
 * no part of one. The model saw such a value in clear, and may repeat only part of it — "Jane" from
 * "Jane Doe", "jdoe" from "CORP\\jdoe", the surname "王" from "王 小明", an initial — which the analyst
 * never approved. So a string that carries the value or any word of it is not proof the model wrote
 * it on its own.
 */
export function withoutVisible(strings: readonly string[], suppressed: readonly string[]): string[] {
  const whole = suppressed.map(normalizeAuthored).filter(Boolean);
  const parts = [...new Set(whole.flatMap((v) => v.split(/[^\p{L}\p{N}]+/u)).filter(Boolean))];
  const anywhere = (p: string) => p.length >= VISIBLE_PART_SUBSTRING_CHARS || CASELESS_LETTER.test(p);
  const long = [...new Set([...whole, ...parts.filter(anywhere)])];
  const short = parts.filter((p) => !anywhere(p)).map(shortPart);
  return strings.filter(
    (s) => !long.some((v) => occurrences(s, v).length > 0) && !short.some((re) => re.test(s)),
  );
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
 * Mask a split prompt. The prompt is masked WHOLE, exactly as it would be with no AI spans, and that
 * is what is sent: a hidden value that crosses a span boundary ("Running notes: Jane Doe") is masked
 * as one value. The spans come from masking each segment too (one anonymizer, so a value keeps its
 * token) and lining the results up against the whole: a span counts only where its segment's
 * masked text sits in the whole at that place. Where a boundary changed the masking, the segments
 * on each side no longer line up, and the spans there are dropped: their values are held.
 */
export function maskSegments(
  segments: readonly PromptSegment[],
  apply: (text: string) => string,
): { masked: string; spans: AuthoredSpan[] } {
  const masked = apply(segments.map((sg) => sg.text).join(""));
  const parts = segments.map((sg) => ({ ...sg, m: apply(sg.text) }));
  const spans: AuthoredSpan[] = [];
  const push = (p: (typeof parts)[number], start: number) => {
    if (p.ai) spans.push({ start, end: start + p.m.length, clipped: p.clipped });
  };
  // From the front, then from the back up to the first segment that did not line up.
  let head = 0;
  let at = 0;
  for (; head < parts.length && masked.startsWith(parts[head].m, at); head++) {
    push(parts[head], at);
    at += parts[head].m.length;
  }
  let end = masked.length;
  for (let i = parts.length - 1; i > head && end - parts[i].m.length >= at; i--) {
    const start = end - parts[i].m.length;
    if (!masked.startsWith(parts[i].m, start)) break;
    push(parts[i], start);
    end = start;
  }
  return { masked, spans: spans.sort((a, b) => a.start - b.start) };
}

/** The gate's view of the AI text. Nothing to skip, or a record that cannot be read: undefined. */
export async function authoredFor(
  store: AiAuthoredTextStore | undefined,
  log: Logger,
  caseId: string,
  call: Pick<AuthoredText, "spans">,
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

/**
 * Which calls may be recorded as AI-written text. The premise of the skip is that the model only ever
 * saw protected prompts, so it cannot have learned a real value that was hidden from it. An answer
 * from a call made with masking or the Presidio gate off breaks that premise: the model saw clear
 * text and may copy a real name into its summary. So the synthesis call runs inside a probe, every
 * prepared call reports whether it was protected, and the answer is recorded only when all were.
 */
const gateProbe = new AsyncLocalStorage<{ calls: number; unprotected: number; answers: unknown[] }>();

/**
 * Run `fn`; `protectedOnly` is true when at least one call ran, and every call was protected.
 * `answers`: each answer the model gave inside, as it wrote it — before placeholders were restored.
 */
export async function withGateProbe<T>(
  fn: () => Promise<T>,
): Promise<{ value: T; protectedOnly: boolean; answers: unknown[] }> {
  const probe = { calls: 0, unprotected: 0, answers: [] as unknown[] };
  const value = await gateProbe.run(probe, fn);
  return { value, protectedOnly: probe.calls > 0 && probe.unprotected === 0, answers: probe.answers };
}

/** sendPrepared's report: the model's answer, parsed, still masked. */
export function reportAnswer(masked: unknown): void {
  gateProbe.getStore()?.answers.push(masked);
}

/** prepareCall's report: did this call run with masking on and the Presidio gate checking it? */
export function reportGate(protectedCall: boolean): void {
  const probe = gateProbe.getStore();
  if (!probe) return;
  probe.calls++;
  if (!protectedCall) probe.unprotected++;
}
