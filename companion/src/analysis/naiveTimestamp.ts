// A naive ISO date-time: a date and a time-of-day with NO zone marker — "2026-01-01T00:30:00",
// "2026-01-01T00:30", "2026-05-28 10:00:00.123". Seconds and their fraction are optional. The
// separator may be a space, which V8 also reads as local time, so it is matched and normalized to
// "T". A date with no time ("2026-05-28") is deliberately EXCLUDED: ECMAScript reads the date-only
// form as UTC already, so it needs no tagging.
const NAIVE_ISO = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)$/;

/**
 * Tag a naive timestamp as UTC — "2026-01-01T00:30:00" → "2026-01-01T00:30:00Z" (#757).
 *
 * This is the other half of `toUtcIso` (analysis/timeUtc.ts). That function converts an explicit
 * offset and leaves a naive time alone, because running it through `Date` would shift it. But leaving
 * it alone only defers the problem: every downstream `Date.parse` then reads it in the SERVER's zone,
 * so the same string means different instants on different machines. The visible damage is at a year
 * boundary — on a UTC+2 server `Date.parse("2026-01-01T00:30:00")` lands in 2025, which made the AI
 * import's year-provenance check (#739) mark a RECORDED year as guessed and so clamp-eligible, and
 * made the year-clamp itself move the event ~364 days.
 *
 * The prompts already declare the intended reading: "if the column carries no timezone, keep the
 * wall-clock time and add 'Z' … never shift a naive time". This does exactly that, and does it
 * LEXICALLY — no `Date` is constructed, so no zone can enter. Applied at the model-output boundary
 * (responseSchema.ts) every consumer downstream sees one unambiguous instant.
 *
 * Anything that is not a naive ISO date-time is returned unchanged: already-UTC, an explicit offset,
 * a BSD syslog "May 28 09:00:01", a date with no time, unparseable text. Empty stays empty. Pure and
 * idempotent (the output carries a "Z", so a second pass does not match).
 *
 * Filed in the SHARED layer, next to regexEscape.ts, precisely so the delta schema can reach it:
 * responseSchema.ts is shared and may not import up into analysis/timeline (see ARCHITECTURE.md).
 */
export function tagNaiveAsUtc(ts: string | undefined | null): string {
  const s = (ts ?? "").trim();
  const m = NAIVE_ISO.exec(s);
  return m ? `${m[1]}T${m[2]}Z` : s;
}
