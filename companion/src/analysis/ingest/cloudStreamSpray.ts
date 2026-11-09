// Password-spray candidates of a streamed import (#2303), read back from the sign-in observation
// store (#2301) the batches appended to — never from the full row set in memory. Run ONCE, after
// the last batch: the within-upload patterns are the ones built from this import's own
// observations; the cross-upload patterns join them with earlier uploads', reported only when no
// single upload's own count already met the threshold (the whole-file path's rule, importState.ts).
// The store's window query is capped (AUTH_OBSERVATION_QUERY_MAX); a capped read is disclosed.
//
// A live collection (#2493) imports each page on its own, so each page's observations carry the
// page's own batch. Its spray is read ONCE by the collection's summary step instead: every page
// batch of the run counts as "own" — one upload — so a spray spread over pages of one run is a
// within-collection pattern, never "across N uploads". Separate uploads keep the cross wording.

import type { ImportContext } from "./importContext.js";
import type { SiemEvent } from "../siemImport.js";
import type { StoredAuthObservation } from "../authObservationStore.js";
import { aggregateEvents } from "../eventAggregate.js";
import {
  passwordSprayPatterns,
  sprayLowSlowHours,
  sprayPatternRows,
  sprayPatternToMappedEvent,
  sprayThreshold,
  SPRAY_PATTERNS_MAX,
  type SprayCandidate,
} from "../passwordSprayFanout.js";

type SprayRows = { events: SiemEvent[]; truncated: boolean };

const toCandidate = (o: StoredAuthObservation): SprayCandidate => ({
  timestamp: o.timestamp,
  account: o.account,
  sourceIp: o.sourceIp,
  hostOrTenant: o.hostOrTenant,
  outcome: o.outcome as SprayCandidate["outcome"],
  locator: o.locator,
  importBatch: o.importBatch,
});

const isSprayAttempt = (o: StoredAuthObservation): boolean =>
  (o.outcome === "failed" || o.outcome === "success") && !!o.sourceIp;

/** The within-upload rows of `idPrefix`'s own candidates, and the cross-upload rows that include it. */
function sprayRowsFrom(candidates: SprayCandidate[], idPrefix: string, truncated: boolean): SprayRows {
  const own = candidates.filter((c) => c.importBatch === idPrefix);
  const meta = { source: "Microsoft 365", importer: "m365" };
  const within = own.length ? sprayPatternRows(own, { ...meta, mappingVersion: "m365-spray-v1" }) : [];
  const threshold = sprayThreshold();
  const cross = passwordSprayPatterns(candidates)
    .filter(
      (p) =>
        p.importBatches.includes(idPrefix) &&
        p.importBatches.length > 1 &&
        Math.max(...Object.values(p.accountsByBatch)) < threshold,
    )
    .slice(0, SPRAY_PATTERNS_MAX)
    .map((p) =>
      sprayPatternToMappedEvent(p, {
        ...meta,
        mappingVersion: "m365-spray-cross-v1",
        crossUpload: true,
        truncatedHistory: truncated,
      }),
    );
  const events = [
    ...aggregateEvents(within, { maxEvents: SPRAY_PATTERNS_MAX + 1 }).events,
    ...aggregateEvents(cross, { maxEvents: SPRAY_PATTERNS_MAX + 1 }).events,
  ];
  return { events, truncated };
}

const sinceFor = (earliestMs: number, retentionHours: number): string =>
  new Date(earliestMs - Math.min(sprayLowSlowHours(), retentionHours) * 3_600_000).toISOString();

export async function streamSprayRows(
  ctx: ImportContext,
  caseId: string,
  idPrefix: string,
  earliest: string,
): Promise<SprayRows> {
  const store = ctx.opts.authObservationStore;
  const earliestMs = Date.parse(earliest);
  if (!store || !Number.isFinite(earliestMs)) return { events: [], truncated: false };
  const since = sinceFor(earliestMs, store.retentionHours());
  const { observations, truncated } = await store.queryWindow(caseId, since, { sprayOnly: true });
  return sprayRowsFrom(observations.filter(isSprayAttempt).map(toCandidate), idPrefix, truncated);
}

/**
 * One live collection's spray rows (#2493): every observation of the run's page batches is
 * relabelled `ownId`, so the run reads as one upload. The look-back starts from the run's own
 * earliest observation, as a file import's does from its own.
 */
export async function collectionSprayRows(
  ctx: ImportContext,
  caseId: string,
  ownId: string,
  pageBatches: ReadonlySet<string>,
): Promise<SprayRows> {
  const store = ctx.opts.authObservationStore;
  if (!store || !pageBatches.size) return { events: [], truncated: false };
  const { observations, truncated } = await store.queryWindow(caseId, new Date(0).toISOString(), {
    sprayOnly: true,
  });
  const attempts = observations.filter(isSprayAttempt);
  const earliestMs = attempts
    .filter((o) => pageBatches.has(o.importBatch))
    .reduce((min, o) => Math.min(min, Date.parse(o.timestamp) || Infinity), Infinity);
  if (!Number.isFinite(earliestMs)) return { events: [], truncated: false };
  const sinceMs = Date.parse(sinceFor(earliestMs, store.retentionHours()));
  const candidates = attempts
    .filter((o) => Date.parse(o.timestamp) >= sinceMs)
    .map((o) => toCandidate(pageBatches.has(o.importBatch) ? { ...o, importBatch: ownId } : o));
  return sprayRowsFrom(candidates, ownId, truncated);
}
