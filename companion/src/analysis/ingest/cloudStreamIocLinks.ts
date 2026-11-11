// The streamed import's IOC links (#2543): the whole-file path resolves each IOC's producing-row
// aggKeys (`sourceAggKeys`, from the IOC sink) against the final event ids into `extractedFrom`
// (cloudAuditImports.ts). A streamed import sees its rows a batch at a time, so the keys are unioned
// across batches here — kept only for rows the budget sent to the forensic timeline as their own
// event — and resolved once the delta's events have their ids. A row that went to the
// super-timeline or into a budget aggregate gives no link: the IOC then simply carries none.

import type { SiemIoc } from "../siemImport.js";
import { STREAM_IOC_LINKS_MAX } from "../cloudStreamLimits.js";

/** The part of the stream accumulator that holds the IOCs. */
export interface StreamIocSink {
  iocs: Map<string, SiemIoc>;
  iocsMax: number;
  /** Distinct IOCs past `iocsMax`, counted for the disclosure (never kept). */
  iocsDropped: number;
}

/** `keys` plus each of `more` not already in it, at most STREAM_IOC_LINKS_MAX. */
function unionKeys(keys: readonly string[], more: readonly string[]): string[] {
  const out = [...keys];
  const seen = new Set(keys);
  for (const k of more) {
    if (out.length >= STREAM_IOC_LINKS_MAX) break;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(k);
    }
  }
  return out;
}

/**
 * Add one batch's IOCs to the sink. `forensicKeys` are the aggKeys of the batch's rows that reached
 * the forensic timeline as their own event; an IOC keeps only those of its producing-row keys, so
 * the links it carries across batches are the ones that can resolve. The first sighting's other
 * fields (type, value, note) stay.
 */
export function noteStreamIocs(
  sink: StreamIocSink,
  iocs: readonly SiemIoc[],
  forensicKeys: ReadonlySet<string>,
): void {
  for (const ioc of iocs) {
    const k = `${ioc.type}|${ioc.value}`;
    const keys = (ioc.sourceAggKeys ?? []).filter((key) => forensicKeys.has(key));
    const existing = sink.iocs.get(k);
    if (existing) {
      if (keys.length)
        sink.iocs.set(k, { ...existing, sourceAggKeys: unionKeys(existing.sourceAggKeys ?? [], keys) });
      continue;
    }
    // Over the cap, a distinct IOC is counted (a later batch may repeat it: counted once per batch).
    if (sink.iocs.size >= sink.iocsMax) {
      sink.iocsDropped++;
      continue;
    }
    const { sourceAggKeys: _all, ...rest } = ioc;
    sink.iocs.set(k, keys.length ? { ...rest, sourceAggKeys: unionKeys([], keys) } : rest);
  }
}

/**
 * Each IOC's `extractedFrom`: the ids of the delta's events whose aggKey is one of its producing-row
 * keys. Several individual High rows can share one aggKey; the IOC links to each of them, at most
 * STREAM_IOC_LINKS_MAX. An IOC with no resolvable key is returned without a link.
 */
export function resolveStreamIocLinks(
  iocs: readonly SiemIoc[],
  events: readonly { id: string; aggKey?: string }[],
): SiemIoc[] {
  const idsByKey = new Map<string, string[]>();
  for (const e of events) {
    if (!e.aggKey) continue;
    idsByKey.set(e.aggKey, [...(idsByKey.get(e.aggKey) ?? []), e.id]);
  }
  return iocs.map((c) => {
    const ids = unionKeys(
      [],
      (c.sourceAggKeys ?? []).flatMap((k) => idsByKey.get(k) ?? []),
    );
    return ids.length ? { ...c, extractedFrom: ids } : c;
  });
}
