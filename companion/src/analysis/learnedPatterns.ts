import type { FalsePositiveReason } from "./falsePositive.js";

// Learn from dismissals (issue #65). The false-positive machinery already EXCLUDES an exact marked
// finding/IOC from the next synthesis (buildFalsePositiveContext) and treats authorized-test/known-good
// tooling as expected-but-watch (buildAuthorizedContextBlock, #13). What it does NOT do is GENERALIZE:
// when the analyst keeps dismissing the same class of thing ("BloodHound findings — red-team exercise"),
// a NEW, not-yet-marked finding of that class should still surface but with LOWER confidence unless
// independently corroborated — not be excluded (it might be the real thing this time), and not sail
// through at full confidence.
//
// This module is the PURE, unit-tested core: it distills reasoned dismissals into an accumulating
// per-case ledger (signature + reason + how often it recurred) and renders the advisory synthesis block.
// The I/O wrapper is learnedPatternStore.ts; the record hook is the false-positive route; the block is
// appended to the synthesis prompt in pipeline.ts. A pattern is keyed by (normalized signature + reason),
// so the same tool dismissed for two different reasons stays two distinct learnings. Reuses the existing
// FalsePositiveReason taxonomy rather than inventing a parallel dismissalReason field.

export interface LearnedPattern {
  id: string;                 // stable key = fingerprint of (signature + reason)
  signature: string;          // normalized dismissed text (finding title / event label)
  reason: FalsePositiveReason;
  count: number;              // times a matching item was dismissed — the recurrence weight
  examples: string[];         // sample dismissed titles (capped), for display + prompt colour
  firstSeen: string;
  lastSeen: string;
}

export interface LearnedPatternInput {
  text: string;               // the finding title / event label the analyst just dismissed
  reason: FalsePositiveReason;
  example?: string;           // concrete example to remember (defaults to `text`)
}

export interface MergeLearnedPatternResult {
  patterns: LearnedPattern[];
  changed: boolean;
}

const MIN_SIGNATURE_LEN = 4;   // below this the text is an opaque id / too generic to generalize from
const MAX_SIGNATURE_LEN = 200;
const MAX_EXAMPLES = 5;
export const LEARNED_PATTERN_MAX = 100;      // per-case ledger cap
export const LEARNED_PATTERN_MIN_COUNT = 1;  // default: every reasoned dismissal is a caution (soft, non-excluding)

// Whitespace-collapse + lowercase so two formattings of the same title fingerprint identically (prose,
// like a hypothesis title — case is not significant). Mirrors hypothesis.ts normalizeTitle.
export function normalizeSignature(text: string): string {
  return String(text ?? "").replace(/\s+/g, " ").trim().toLowerCase();
}

// The learnable signature for a dismissed item, or "" when the text is too short/opaque to generalize
// from (e.g. a bare event id like "e12") — the caller then skips recording.
export function deriveSignature(text: string): string {
  const norm = normalizeSignature(text).slice(0, MAX_SIGNATURE_LEN);
  return norm.length >= MIN_SIGNATURE_LEN ? norm : "";
}

// Deterministic FNV-1a fingerprint of (signature | reason) — the stable upsert key (mirrors
// hypothesis.ts hypothesisAutoKey). Same tool + same reason → same pattern; differing reason → distinct.
export function learnedPatternKey(signature: string, reason: FalsePositiveReason): string {
  const basis = `${signature}|${reason}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < basis.length; i++) {
    h ^= basis.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return `lp:${(h >>> 0).toString(16)}`;
}

// Upsert one reasoned dismissal into the ledger. New signature → fresh pattern (count 1); a recurrence
// bumps count, refreshes lastSeen, and appends the example (deduped, capped). A too-short/opaque text is
// ignored (no-op). Pure + deterministic: pass `now` in; capped at LEARNED_PATTERN_MAX (oldest-first drop).
export function mergeLearnedPattern(
  existing: readonly LearnedPattern[],
  input: LearnedPatternInput,
  now: string,
): MergeLearnedPatternResult {
  const signature = deriveSignature(input.text);
  if (!signature) return { patterns: [...existing], changed: false };
  const id = learnedPatternKey(signature, input.reason);
  const example = String(input.example ?? input.text ?? "").trim().slice(0, MAX_SIGNATURE_LEN);
  const patterns = existing.map((p) => ({ ...p, examples: [...p.examples] }));
  const cur = patterns.find((p) => p.id === id);
  if (cur) {
    cur.count += 1;
    cur.lastSeen = now;
    if (example && !cur.examples.includes(example)) cur.examples = [...cur.examples, example].slice(-MAX_EXAMPLES);
    return { patterns, changed: true };
  }
  patterns.push({
    id, signature, reason: input.reason, count: 1,
    examples: example ? [example] : [],
    firstSeen: now, lastSeen: now,
  });
  // Cap the ledger: keep the most recently-seen patterns (drop stale one-offs first).
  if (patterns.length > LEARNED_PATTERN_MAX) {
    patterns.sort((a, b) => (a.lastSeen < b.lastSeen ? -1 : a.lastSeen > b.lastSeen ? 1 : 0));
    patterns.splice(0, patterns.length - LEARNED_PATTERN_MAX);
  }
  return { patterns, changed: true };
}

// The learned patterns a NEW finding title matches — bidirectional substring on the normalized signature
// (same match semantics as applyFalsePositive's finding match). Used for display/highlighting; synthesis
// down-weighting is done by the model via the rendered block below.
export function matchLearnedPatterns(findingTitle: string, patterns: readonly LearnedPattern[]): LearnedPattern[] {
  const title = normalizeSignature(findingTitle);
  if (!title) return [];
  return patterns.filter((p) => p.signature && (title.includes(p.signature) || p.signature.includes(title)));
}

// The advisory synthesis block. Distinct from buildFalsePositiveContext (EXCLUDE exact markers) and
// buildAuthorizedContextBlock (#13, treat sanctioned tooling as expected): this tells the model that NEW
// activity resembling a repeatedly-dismissed pattern should be surfaced with LOWER confidence unless
// independently corroborated — never silently dropped. Only patterns with count ≥ minCount are shown
// (a recurrence threshold); returns "" when none qualify. Sorted by recurrence, capped for prompt size.
export function buildLearnedPatternsBlock(
  patterns: readonly LearnedPattern[],
  minCount: number = LEARNED_PATTERN_MIN_COUNT,
  max = 25,
): string {
  const threshold = Math.max(1, Math.floor(minCount));
  const shown = patterns
    .filter((p) => p.count >= threshold)
    .slice()
    .sort((a, b) => b.count - a.count || a.signature.localeCompare(b.signature))
    .slice(0, Math.max(0, max));
  if (!shown.length) return "";
  const lines = shown
    .map((p) => `- "${p.signature}" [${p.reason}] — dismissed ${p.count}×${p.examples.length ? ` (e.g. ${p.examples[0]})` : ""}`)
    .join("\n");
  return (
    "PREVIOUSLY DISMISSED PATTERNS (the analyst has repeatedly ruled these out on THIS case). For NEW " +
    "activity that RESEMBLES one of these, do NOT exclude it — it may be the real thing this time — but " +
    "LOWER its confidence and flag it as needing independent corroboration before treating it as a threat:\n" +
    lines
  );
}
