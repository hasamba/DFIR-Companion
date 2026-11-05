// MFA-fatigue rows for one M365 import (#2306), shared by the whole-file path (cloudImports.ts) and
// the streamed path (cloudStreamImport.ts) so both read the same evidence the same way. Run once per
// import, AFTER the import's sign-in observations were appended to the store: the read-back covers
// this import's observations, every batch of a streamed import, and earlier imports' observations
// in one combined, deterministic pass (mfaFatigue.ts).
//
// The read is bounded to [earliest − window, latest + window] of this import's own evidence time —
// an episode involving this import's observations has its success inside that span, and depends only
// on observations within the window before it. The read pages through the store (never the
// super-timeline) and stops at AUTH_OBSERVATION_QUERY_MAX rows, which is disclosed on the row.
// Without a store (minimal / test wirings) the pass runs over this import's own observations only.

import type { ImportContext } from "./importContext.js";
import type { SiemEvent } from "../siemImport.js";
import { aggregateEvents } from "../eventAggregate.js";
import {
  AUTH_OBSERVATION_QUERY_MAX,
  type AuthObservationCursor,
  type StoredAuthObservation,
} from "../authObservationStore.js";
import {
  fatigueRows,
  isFatiguePrompt,
  newFatigueEpisodes,
  MFA_FATIGUE_PATTERNS_MAX,
  MFA_FATIGUE_WINDOW_MINUTES,
} from "../mfaFatigue.js";

const PAGE = 5_000;

export interface FatigueSpan {
  earliest: string; // ISO — this import's earliest sign-in observation
  latest: string; // ISO — its latest
}

export interface FatigueResult {
  events: SiemEvent[];
  truncated: boolean;
}

const relevant = (o: StoredAuthObservation): boolean =>
  o.importer === "m365" && (o.outcome === "success" || isFatiguePrompt(o));

/** The span of these observations' evidence time, or null when none carries a readable time. */
export function fatigueSpan(
  observations: ReadonlyArray<Pick<StoredAuthObservation, "timestamp">>,
): FatigueSpan | null {
  let earliest = "";
  let latest = "";
  for (const { timestamp } of observations) {
    if (!Number.isFinite(Date.parse(timestamp))) continue;
    if (!earliest || timestamp < earliest) earliest = timestamp;
    if (timestamp > latest) latest = timestamp;
  }
  return earliest ? { earliest, latest } : null;
}

async function readSpan(
  ctx: ImportContext,
  caseId: string,
  span: FatigueSpan,
): Promise<{ observations: StoredAuthObservation[]; truncated: boolean } | null> {
  const store = ctx.opts.authObservationStore;
  const lo = Date.parse(span.earliest);
  const hi = Date.parse(span.latest);
  if (!store || !Number.isFinite(lo) || !Number.isFinite(hi)) return null;
  const windowMs = MFA_FATIGUE_WINDOW_MINUTES * 60_000;
  const since = new Date(lo - windowMs).toISOString();
  const until = new Date(hi + windowMs).toISOString();
  const observations: StoredAuthObservation[] = [];
  let read = 0;
  let after: AuthObservationCursor | undefined;
  for (;;) {
    const page = await store.queryPage(caseId, { since, until, after, limit: PAGE });
    read += page.observations.length;
    observations.push(...page.observations.filter(relevant));
    if (!page.next) return { observations, truncated: false };
    if (read >= AUTH_OBSERVATION_QUERY_MAX) return { observations, truncated: true };
    after = page.next;
  }
}

/**
 * The fatigue rows this import makes new. `own` is this import's own observations — the span when
 * `span` is omitted (whole-file path), and the whole input when the case has no observation store.
 */
export async function mfaFatigueRows(
  ctx: ImportContext,
  caseId: string,
  idPrefix: string,
  own: ReadonlyArray<Omit<StoredAuthObservation, "importBatch">>,
  span: FatigueSpan | null = fatigueSpan(own),
): Promise<FatigueResult> {
  if (!span) return { events: [], truncated: false };
  const stored = await readSpan(ctx, caseId, span);
  const observations = stored?.observations ?? own.map((o) => ({ ...o, importBatch: idPrefix }));
  const truncated = stored?.truncated ?? false;
  const episodes = newFatigueEpisodes(observations, idPrefix);
  if (!episodes.length) return { events: [], truncated };
  const rows = fatigueRows(episodes, { truncatedHistory: truncated });
  return { events: aggregateEvents(rows, { maxEvents: MFA_FATIGUE_PATTERNS_MAX + 1 }).events, truncated };
}
