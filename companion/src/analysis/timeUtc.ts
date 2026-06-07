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
// Sub-millisecond precision is preserved: JS `Date` is millisecond-resolution, so converting an
// offset timestamp through it silently drops microseconds/nanoseconds (e.g. Suricata's
// "…22.789338+0000" would become "…22.789Z"). A timezone offset only shifts whole minutes, so the
// fractional seconds are INVARIANT under the conversion — we re-attach the original fraction when it
// is finer than milliseconds, so forensic precision isn't lost.
//
// Empty stays empty. Pure and idempotent (applying it twice is a no-op).
const TZ_OFFSET = /[+-]\d{2}:?\d{2}$/; // a trailing numeric timezone offset, e.g. +02:00 / -0500
const SUBSEC = /\.(\d+)(?=[+-]\d{2}:?\d{2}$)/; // fractional seconds immediately before that offset

export function toUtcIso(ts: string | undefined | null): string {
  const s = (ts ?? "").trim();
  if (!s || !TZ_OFFSET.test(s)) return s;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  const iso = d.toISOString(); // canonical UTC, but truncated to milliseconds (…SS.mmmZ)
  const frac = SUBSEC.exec(s); // re-attach finer-than-ms precision the Date round-trip dropped
  return frac && frac[1].length > 3 ? iso.replace(/\.\d{3}Z$/, `.${frac[1]}Z`) : iso;
}
