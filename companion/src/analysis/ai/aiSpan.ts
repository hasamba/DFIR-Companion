import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";

/**
 * Where a prompt holds text the synthesis model wrote — the provenance the Presidio gate needs to
 * skip it (see presidioAuthoredText.ts).
 *
 * WHY MARKERS AND NOT TEXT MATCHING. Two adversarial reviews showed that matching recorded AI text
 * against the finished prompt cannot work: an event or an analyst note that repeats AI prose is the
 * same characters in the same frame, and every rule that told them apart had a counter-example. So
 * the prompt builders say where they put an AI field, and the gate trusts only that.
 *
 * THE MARKERS NEVER LEAVE THIS PROCESS. prepareCall splits them out before masking and sends the
 * prompt without them, so the model, the logs and every saved prompt see exactly the text they saw
 * before. They are private-use characters plus a per-process random nonce: adversary-controlled
 * event text cannot forge one, and a marker with another nonce (a prompt saved by an earlier
 * process) is stripped and trusted as nothing. Private-use characters, not hex: a long hex run reads
 * as an API key to the secret redactor, which would eat the marker.
 *
 * OPT-IN BY SCOPE. aiSpan() marks text only inside withAiSpans(), which the two production prompt
 * builds open (synthesis and the 2nd-opinion referee). Anywhere else — a test calling a builder, a
 * report prompt — it returns the text unchanged, and the gate then skips nothing there.
 */

const OPEN_FULL = "";
const OPEN_CLIPPED = "";
const CLOSE = "";
const NONCE_CHARS = 8;
const NONCE = [...randomBytes(NONCE_CHARS)].map((b) => String.fromCharCode(0xe100 + b)).join("");
/** Any marker of any process, and any stray marker character, so a stale one is removed too. */
const ANY_MARK = new RegExp(`[\\uE000-\\uE002][\\uE100-\\uE1FF]{${NONCE_CHARS}}|[\\uE000-\\uE002]`, "g");

const scope = new AsyncLocalStorage<true>();

/** Run `fn` with aiSpan() marking. The scope follows every await inside it. */
export function withAiSpans<T>(fn: () => T): T {
  return scope.run(true, fn);
}

/**
 * Mark one AI field as the prompt prints it. `clipped`: the builder cut the text (the referee's
 * 240-character description, clipText's "…"), so the gate matches it as the start of a recorded
 * string, not the whole of one. Wrap the RENDERED text, after any cut, so the span is exactly what
 * the prompt shows.
 */
export function aiSpan(text: string, clipped = false): string {
  if (!scope.getStore() || !text) return text;
  return `${clipped ? OPEN_CLIPPED : OPEN_FULL}${NONCE}${text}${CLOSE}${NONCE}`;
}

/** The text with every marker removed — what is sent, logged or saved. */
export function stripAiSpans(text: string): string {
  return text.replace(ANY_MARK, "");
}

/** One run of prompt text: AI-marked (`ai`), and whether the builder cut it. */
export interface PromptSegment {
  text: string;
  ai: boolean;
  clipped: boolean;
}

/**
 * Split a marked prompt into plain and AI segments, markers removed. Only this process's markers
 * open a segment; an open marker without its close is not trusted, so its text is plain.
 */
export function splitAiSpans(marked: string): PromptSegment[] {
  const out: PromptSegment[] = [];
  const plain = (text: string) => {
    const t = stripAiSpans(text);
    if (t) out.push({ text: t, ai: false, clipped: false });
  };
  const closeMark = CLOSE + NONCE;
  let at = 0;
  for (;;) {
    const open = nextOpen(marked, at);
    if (!open) break;
    const close = marked.indexOf(closeMark, open.end);
    const inner = close < 0 ? "" : marked.slice(open.end, close);
    if (close < 0 || nextOpen(inner, 0)) {
      plain(marked.slice(at)); // unbalanced or nested: trust none of it
      return out;
    }
    plain(marked.slice(at, open.start));
    const text = stripAiSpans(inner);
    if (text) out.push({ text, ai: true, clipped: open.clipped });
    at = close + closeMark.length;
  }
  plain(marked.slice(at));
  return out;
}

function nextOpen(text: string, from: number): { start: number; end: number; clipped: boolean } | null {
  const full = text.indexOf(OPEN_FULL + NONCE, from);
  const clip = text.indexOf(OPEN_CLIPPED + NONCE, from);
  const start = full < 0 ? clip : clip < 0 ? full : Math.min(full, clip);
  if (start < 0) return null;
  return { start, end: start + 1 + NONCE_CHARS, clipped: start === clip };
}
