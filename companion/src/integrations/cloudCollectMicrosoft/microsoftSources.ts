// What the Microsoft collector (#2315) can collect, with the #2312 limits each source declares.
//
// Graph's identity reports (sign-ins AND directory audits) share one limit — 5 requests per 10 s
// per app per tenant — so every Entra source names the same rate-limit group. The unified audit log
// is queried, not listed: each new sub-window costs one submission from the tenant's rolling-24 h
// quota, and a capped window splits to one minute, then per record type.

import type { CollectSourceInfo } from "../cloudCollect/collectTypes.js";
import {
  DEFAULT_OVERLAP_MS,
  MIN_WINDOW_MS,
  PARTITION_KEYS,
  RATE_LIMITS,
  RETENTION,
} from "../cloudCollect/collectDefaults.js";
import { AZURE_ACTIVITY_SOURCE } from "./azureActivitySource.js";
import { DIRECTORY_AUDITS_SOURCE, SIGN_IN_CATEGORIES } from "./entraSources.js";
import { UAL_RECORD_TYPES } from "./ualRecordTypes.js";

export const UAL_SOURCE = "m365-ual";
const ENTRA_RATE = { ...RATE_LIMITS.graphSignIns, group: "graph-identity-reports" };

const entra = (id: string, label: string): CollectSourceInfo => ({
  id,
  label,
  streamKind: "m365",
  minWindowMs: MIN_WINDOW_MS.graph,
  rateLimit: ENTRA_RATE,
  overlapMs: DEFAULT_OVERLAP_MS.microsoft,
  retention: RETENTION.entra,
});

export const MICROSOFT_SOURCES: readonly CollectSourceInfo[] = [
  {
    id: UAL_SOURCE,
    label: "Microsoft 365 unified audit log (Graph audit log query)",
    streamKind: "m365",
    minWindowMs: MIN_WINDOW_MS.graph,
    partition: { key: PARTITION_KEYS.graph, values: UAL_RECORD_TYPES },
    queryCost: 1,
    overlapMs: DEFAULT_OVERLAP_MS.microsoft,
    retention: RETENTION.unifiedAuditLog,
  },
  entra(DIRECTORY_AUDITS_SOURCE, "Entra directory audit logs"),
  ...Object.entries(SIGN_IN_CATEGORIES).map(([id, c]) => entra(id, `Entra sign-ins — ${c.label}`)),
  {
    id: AZURE_ACTIVITY_SOURCE,
    label: "Azure Activity log (every subscription the app can read)",
    streamKind: "cloud",
    overlapMs: DEFAULT_OVERLAP_MS.microsoft,
    retention: RETENTION.azureActivity,
  },
];

/** What the collector does NOT collect — shown under the sources in the panel. */
export const MICROSOFT_NOTES: readonly string[] = [
  "Not collected live: mailbox audit, transport rules and message trace. Graph has no stable API " +
    "for them; collect them with Microsoft Extractor Suite (MES) and import the export — the " +
    "cloud tool compatibility matrix in the manual (#2300) says which file covers what.",
  "Search-UnifiedAuditLog is never used (it retires on 2027-10-15): the unified audit log comes " +
    "from Graph audit log queries, which can take 10 minutes or more each before the first page.",
];
