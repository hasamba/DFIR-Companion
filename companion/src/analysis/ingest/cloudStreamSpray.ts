// Password-spray candidates of a streamed import (#2303), read back from the sign-in observation
// store (#2301) the batches appended to — never from the full row set in memory. Run ONCE, after
// the last batch: the within-upload patterns are the ones built from this import's own
// observations; the cross-upload patterns join them with earlier uploads', reported only when no
// single upload's own count already met the threshold (the whole-file path's rule, importState.ts).
// The store's window query is capped (AUTH_OBSERVATION_QUERY_MAX); a capped read is disclosed.

import type { ImportContext } from "./importContext.js";
import type { SiemEvent } from "../siemImport.js";
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

export async function streamSprayRows(
  ctx: ImportContext,
  caseId: string,
  idPrefix: string,
  earliest: string,
): Promise<{ events: SiemEvent[]; truncated: boolean }> {
  const store = ctx.opts.authObservationStore;
  const earliestMs = Date.parse(earliest);
  if (!store || !Number.isFinite(earliestMs)) return { events: [], truncated: false };
  const windowHours = Math.min(sprayLowSlowHours(), store.retentionHours());
  const since = new Date(earliestMs - windowHours * 3_600_000).toISOString();
  const { observations, truncated } = await store.queryWindow(caseId, since, { sprayOnly: true });
  const candidates: SprayCandidate[] = observations
    .filter((o) => (o.outcome === "failed" || o.outcome === "success") && o.sourceIp)
    .map((o) => ({
      timestamp: o.timestamp,
      account: o.account,
      sourceIp: o.sourceIp,
      hostOrTenant: o.hostOrTenant,
      outcome: o.outcome as SprayCandidate["outcome"],
      locator: o.locator,
      importBatch: o.importBatch,
    }));
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
