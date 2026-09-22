// The import-scoped IOC sink shared by every deterministic importer (moved out of siemImport.ts
// under the file-size ledger, #1266): dedup by type+value, the per-row -> per-file merge that keeps
// every producing row's aggKey, and the final aggKey -> case-event-id resolution into extractedFrom.
import { isNonIndicatorVendorIp } from "./ipHygiene.js";
import type { IocProvenance } from "./stateTypes.js";

export interface SiemIoc {
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "sid" | "other";
  value: string;
  // Import-scoped only: the aggKey(s) of the row(s) that produced this IOC within one parse call.
  // Resolved to real case-scoped event ids by pipeline.ts and converted into `extractedFrom`;
  // never itself persisted into case state.
  sourceAggKeys?: string[];
  // Case-scoped event id(s) this IOC was authoritatively extracted from. Set by pipeline.ts after
  // resolving sourceAggKeys; empty/absent falls back to iocProvenanceChain.ts's approximate matcher.
  extractedFrom?: string[];
  provenance?: IocProvenance; // #1266 — see stateTypes.ts; plain (absent) wins over marked at every sink
}

// An address inside a vendor's own single-tenant service space is a fact about the vendor, not an
// indicator (#1530). Twelve Microsoft and Akamai service addresses sat in one case's IOC list as
// type `ip`, indistinguishable from the six real C2 addresses, and the attack graph offered all
// eighteen as candidate C2. They are kept — with their event links, their dedup and their note (the
// merge writes `vendor: …` beside the value) — as type `other`, which is the type that means
// "recorded, not accused". It also keeps threat-intel quota off Microsoft's CDN. Multi-tenant edge
// space (Cloudflare) is deliberately NOT retyped: anyone can front C2 behind it, so the analyst is
// told whose edge it is and the address stays a full indicator.
function effectiveType(type: SiemIoc["type"], value: string): SiemIoc["type"] {
  return type === "ip" && isNonIndicatorVendorIp(value) ? "other" : type;
}

export function addIoc(
  sink: Map<string, SiemIoc>,
  rawType: SiemIoc["type"],
  value: string,
  provenance?: IocProvenance,
): void {
  const v = value.trim();
  if (!v) return;
  // The key must be computed from the type actually stored, or the map key and the record disagree.
  const type = effectiveType(rawType, v);
  const key = `${type}:${v.toLowerCase()}`;
  const existing = sink.get(key);
  if (!existing) sink.set(key, { type, value: v, ...(provenance ? { provenance } : {}) });
  // #1266: plain wins, order-independently — a later ordinary sighting un-marks, a later marked one
  // cannot mark. The same rule is applied again at mergeRowIocs and stateMerge.
  else if (existing.provenance && !provenance) {
    const { provenance: _dropped, ...plain } = existing;
    sink.set(key, plain);
  }
}

// Merge a per-row IOC sink into the file-level sink once that row's aggKey (from its MappedEvent)
// is known, unioning sourceAggKeys so a value seen across multiple rows keeps every row's link.
// Call with no aggKey for a row that produced IOCs but no event (e.g. non-alert network telemetry)
// — the value still merges in, just without a link, matching today's approximate-only behavior.
export function mergeRowIocs(
  fileSink: Map<string, SiemIoc>,
  rowSink: Map<string, SiemIoc>,
  aggKey?: string,
): void {
  for (const [key, ioc] of rowSink) {
    const existing = fileSink.get(key);
    const keys = existing?.sourceAggKeys ?? [];
    const nextKeys = aggKey && !keys.includes(aggKey) ? [...keys, aggKey] : keys;
    // #1266: plain wins here too — `...(existing ?? ioc)` alone would make the marker first-wins.
    const { provenance: _dropped, ...base } = existing ?? ioc;
    const provenance = existing
      ? existing.provenance && ioc.provenance
        ? existing.provenance
        : undefined
      : ioc.provenance;
    fileSink.set(key, {
      ...base,
      ...(provenance ? { provenance } : {}),
      ...(nextKeys.length ? { sourceAggKeys: nextKeys } : {}),
    });
  }
}

// Resolve each IOC's sourceAggKeys against a final aggKey->event-id lookup (built once events have
// their case-scoped ids), stamping extractedFrom. An aggKey with no match (e.g. the event was
// capped by maxEvents) is silently dropped — that IOC just falls back to approximate matching.
export function resolveExtractedFrom(
  iocs: readonly SiemIoc[],
  eventIdByAggKey: ReadonlyMap<string, string>,
): SiemIoc[] {
  return iocs.map((c) => {
    if (!c.sourceAggKeys?.length) return c;
    const ids = [
      ...new Set(c.sourceAggKeys.map((k) => eventIdByAggKey.get(k)).filter((x): x is string => !!x)),
    ];
    return ids.length ? { ...c, extractedFrom: ids } : c;
  });
}
