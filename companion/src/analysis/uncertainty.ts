import { UNCERTAINTY_STATUSES, type Uncertainty, type UncertaintyStatus } from "./stateTypes.js";

// Structured analytical-uncertainty ledger (issue #73). Turns the raw synthesis `uncertainties` array
// into clean, deterministic entries: require a topic (skip blanks), coerce the status to the enum
// (default "unknown" — never over-claim), trim/cap the prose, dedupe by normalized topic (first wins),
// and cap the count. Pure — no I/O, no clock. Mirrors the sanitize posture of sanitizeHypotheses.

export const UNCERTAINTY_MAX_DEFAULT = 30; // cap on entries kept per synthesis
const MAX_TOPIC_LEN = 200;
const MAX_TEXT_LEN = 1000;

const VALID_STATUS = new Set<string>(UNCERTAINTY_STATUSES);

export function sanitizeUncertainties(
  raw: readonly unknown[] | undefined,
  max: number = UNCERTAINTY_MAX_DEFAULT,
): Uncertainty[] {
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : UNCERTAINTY_MAX_DEFAULT;
  const seen = new Set<string>();
  const out: Uncertainty[] = [];
  for (const item of raw ?? []) {
    const u = (item ?? {}) as Record<string, unknown>;
    const topic = String(u.topic ?? "").trim().slice(0, MAX_TOPIC_LEN);
    if (!topic) continue;
    const key = topic.replace(/\s+/g, " ").toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const status = String(u.status ?? "").trim().toLowerCase();
    out.push({
      topic,
      status: VALID_STATUS.has(status) ? (status as UncertaintyStatus) : "unknown",
      basis: String(u.basis ?? "").trim().slice(0, MAX_TEXT_LEN),
      gap: String(u.gap ?? "").trim().slice(0, MAX_TEXT_LEN),
    });
    if (out.length >= cap) break;
  }
  return out;
}
