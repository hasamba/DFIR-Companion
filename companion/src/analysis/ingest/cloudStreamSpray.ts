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
// Every collection's pages fold into ONE upload this way — earlier collections too, wherever spray
// is read — so cross-upload dominance and "across N uploads" count a collection once.
//
// THE COLLECTION'S OWN OBSERVATIONS ARE READ IN FULL. The store's window query is capped at the
// newest AUTH_OBSERVATION_QUERY_MAX rows case-wide, and newer uploads can fill it; the run's own
// observations are therefore paged through without a cap. Only the OTHER uploads' rows come from
// the capped window, and a capped read is reported (`truncated`) so the caller never treats an
// incomplete history as the whole story.

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

// A collection page's batch is `cc<short>p<seq>` (pageIdPrefix, integrations/cloudCollect/
// collectSummary.ts); every page of one collection shares `cc<short>`. A file upload's batch never
// has this shape.
const PAGE_BATCH = /^(cc[A-Za-z0-9]{1,8})p\d+$/;

/** The upload a batch belongs to: a collection page's collection (`cc<short>`), else the batch itself. */
export function uploadBatchOf(batch: string): string {
  return PAGE_BATCH.exec(batch)?.[1] ?? batch;
}

const toCandidate = (o: StoredAuthObservation): SprayCandidate => ({
  timestamp: o.timestamp,
  account: o.account,
  sourceIp: o.sourceIp,
  hostOrTenant: o.hostOrTenant,
  outcome: o.outcome as SprayCandidate["outcome"],
  locator: o.locator,
  importBatch: uploadBatchOf(o.importBatch),
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

type AuthStore = NonNullable<ImportContext["opts"]["authObservationStore"]>;

/** Every stored spray attempt of `upload`, paged through without the window query's cap. */
async function ownAttempts(
  store: AuthStore,
  caseId: string,
  upload: string,
): Promise<StoredAuthObservation[]> {
  const own: StoredAuthObservation[] = [];
  let after: { ms: number; rowId: number } | undefined;
  do {
    const page = await store.queryPage(caseId, after ? { after } : {});
    for (const o of page.observations)
      if (isSprayAttempt(o) && uploadBatchOf(o.importBatch) === upload) own.push(o);
    after = page.next ?? undefined;
  } while (after);
  return own;
}

/**
 * One live collection's spray rows (#2493): every observation of the run's page batches counts as
 * one upload (the collection). The look-back starts from the run's own earliest observation, as a
 * file import's does from its own. `truncated` is true when the other uploads' history was capped.
 */
export async function collectionSprayRows(
  ctx: ImportContext,
  caseId: string,
  pageBatches: ReadonlySet<string>,
): Promise<SprayRows> {
  const store = ctx.opts.authObservationStore;
  const [first] = pageBatches;
  if (!store || first === undefined) return { events: [], truncated: false };
  const upload = uploadBatchOf(first);
  const own = await ownAttempts(store, caseId, upload);
  const earliestMs = own.reduce((min, o) => Math.min(min, Date.parse(o.timestamp) || Infinity), Infinity);
  if (!Number.isFinite(earliestMs)) return { events: [], truncated: false };
  const since = sinceFor(earliestMs, store.retentionHours());
  const { observations, truncated } = await store.queryWindow(caseId, since, { sprayOnly: true });
  const others = observations.filter((o) => isSprayAttempt(o) && uploadBatchOf(o.importBatch) !== upload);
  return sprayRowsFrom([...own, ...others].map(toCandidate), upload, truncated);
}
