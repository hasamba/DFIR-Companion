// Normalize a forensic timestamp to UTC. Timestamps reach the timeline from many sources — a
// vision model reading a screenshot, CSV/log extraction, THOR JSON, manual entry — and the
// timeline + report declare every time to be UTC. This converts a timestamp that carries an
// explicit numeric timezone OFFSET (e.g. "2026-05-28T10:00:00+02:00") to canonical UTC ("…Z").
//
// Intentionally conservative — it leaves two cases UNCHANGED:
//   • already-UTC ("…Z"): reformatting via Date would only add ".000" noise.
//   • timezone-less / "naive" ("2026-05-28T10:00:00", "May 28 09:00:01") or unparseable: we must
//     NOT run these through `new Date()`, which reinterprets a naive time in the SERVER's local
//     zone and silently shifts it. The prompts instruct the model to emit naive times as UTC.
//
// Empty stays empty. Pure and idempotent (applying it twice is a no-op).
const TZ_OFFSET = /[+-]\d{2}:?\d{2}$/; // a trailing numeric timezone offset, e.g. +02:00 / -0500

export function toUtcIso(ts: string | undefined | null): string {
  const s = (ts ?? "").trim();
  if (!s || !TZ_OFFSET.test(s)) return s;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toISOString();
}
