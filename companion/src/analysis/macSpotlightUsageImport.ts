// mac_apt's (ydkhatri) Spotlight store-item CSV export — one row per indexed item, filtered to
// rows carrying at least one usage/download signal (#933 item 10, "933.10"). Schema verified live
// against spotlight.py's own ProcessStoreItem()/CreateViewAndIndexes(): every multi-value kMDItem*
// attribute is comma-joined by the tool BEFORE it reaches CSV, so this importer keeps those fields
// as flattened text rather than re-splitting them (a legitimately comma-containing value, e.g. a
// download URL's query string, would mis-split). See RECOMMENDATION-11.md for the full research
// trail, including the design-review rejection that caught this exact mismatch.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { parseCsvRecords } from "./csvImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { MAX_FIELD_LEN, SPOTLIGHT_USAGE_BASIS } from "./canonicalSpotlightUsage.js";
import type { MappedEvent, SiemEvent } from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";

export const MAX_SPOTLIGHT_ROWS_SCANNED = 20_000; // report-wide

export interface MacSpotlightUsageOptions {
  aggregate?: boolean;
  maxEvents?: number;
  /** The uploaded file's own name (opts.label from the ingest wrapper) — the CSV's own content
   * carries no store-file identity field, so this is the only available source, best-effort only. */
  sourceLabel?: string;
}

export interface MacSpotlightUsageResult {
  events: SiemEvent[];
  iocs: [];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedRows: number;
  filteredNoSignalRows: number;
  rowsTruncated: boolean;
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max);
}

// Case-insensitive column lookup — mac_apt's own header casing (`ID`, `Date_Updated`,
// `kMDItemUseCount`, ...) differs from the lowercase set the detector's header set uses.
function col(header: string[], row: string[], name: string): string {
  const i = header.findIndex((h) => h.trim().toLowerCase() === name.toLowerCase());
  return i === -1 ? "" : (row[i] ?? "").trim();
}

function isValidHeader(header: string[]): boolean {
  const lower = header.map((h) => h.trim().toLowerCase());
  if (!lower.includes("id") || !lower.includes("date_updated")) return false;
  return (
    lower.includes("kmditemusecount") ||
    lower.includes("kmditemlastuseddate") ||
    lower.includes("kmditemuseddates") ||
    lower.includes("kmditemdownloadeddate") ||
    lower.includes("kmditemwherefroms")
  );
}

function deriveStoreIdentity(sourceLabel: string | undefined): {
  storeIdentity: string;
  storeIdentitySource: "upload-label" | "unavailable";
} {
  const stripped = (sourceLabel ?? "").replace(/^\d+_/, "");
  if (!stripped) return { storeIdentity: "", storeIdentitySource: "unavailable" };
  return { storeIdentity: clip(stripped, MAX_FIELD_LEN), storeIdentitySource: "upload-label" };
}

function mapRow(
  header: string[],
  row: string[],
  reportFingerprint: string,
  storeIdentity: string,
  storeIdentitySource: "upload-label" | "unavailable",
): MappedEvent | "no-signal" | null {
  const itemId = col(header, row, "ID");
  if (!itemId) return null;
  const parentIdRaw = col(header, row, "Parent_ID");
  const dateUpdated = col(header, row, "Date_Updated");
  const displayNameRaw = col(header, row, "kMDItemDisplayName") || col(header, row, "_kMDItemFileName");
  const displayNameSource: "kMDItemDisplayName" | "_kMDItemFileName" | "unavailable" = col(
    header,
    row,
    "kMDItemDisplayName",
  )
    ? "kMDItemDisplayName"
    : col(header, row, "_kMDItemFileName")
      ? "_kMDItemFileName"
      : "unavailable";
  const pathRaw = col(header, row, "FullPath"); // present only on a consolidated export that already resolved it
  const useCountRaw = col(header, row, "kMDItemUseCount");
  const lastUsedDate = col(header, row, "kMDItemLastUsedDate");
  const usedDatesRaw = col(header, row, "kMDItemUsedDates");
  const downloadedDateRaw = col(header, row, "kMDItemDownloadedDate");
  const whereFromsRaw = col(header, row, "kMDItemWhereFroms");

  // Explicit `0` is a real reported value, never conflated with "absent" — checked by presence of
  // a digits-only string, never truthiness (the design's own corrected lesson).
  const useCount = /^\d+$/.test(useCountRaw) ? Number(useCountRaw) : undefined;
  const hasSignal =
    useCount !== undefined || !!lastUsedDate || !!usedDatesRaw || !!downloadedDateRaw || !!whereFromsRaw;
  if (!hasSignal) return "no-signal";

  const findingId = createHash("sha256")
    .update(
      JSON.stringify([
        storeIdentity,
        itemId,
        parentIdRaw,
        displayNameRaw,
        pathRaw,
        useCountRaw,
        lastUsedDate,
        usedDatesRaw,
        downloadedDateRaw,
        whereFromsRaw,
        dateUpdated,
      ]),
    )
    .digest("hex");
  const aggKey = boundedAggKey(`mac-spotlight-usage|${reportFingerprint}|${findingId}`);

  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const nameLabel = displayNameRaw || `item ${itemId}`;
  const signalBits = [
    useCount !== undefined ? `useCount=${useCount}` : "",
    lastUsedDate ? `lastUsed=${lastUsedDate}` : "",
    downloadedDateRaw ? `downloaded=${downloadedDateRaw}` : "",
    whereFromsRaw ? "whereFroms present" : "",
  ]
    .filter(Boolean)
    .join(", ");
  const body = clip(
    `spotlight usage: ${nameLabel} — ${signalBits || "no usage signal"}; corroboration only, never ` +
      `proof of execution or continued existence`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  return {
    timestamp: lastUsedDate,
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["mac_apt-spotlight"],
    canonical: createCanonicalEvent({
      event: { category: "file", type: "mac-spotlight-usage", action: "reported" },
      time: {
        observed: lastUsedDate,
        normalized: lastUsedDate,
        precision: "date",
        clockConfidence: lastUsedDate ? "inferred" : "unknown",
      },
      evidence: {
        rawRecords: [{ source: "mac_apt-spotlight", locator: `item:${findingId.slice(0, 16)}` }],
      },
      producer: {
        importer: "mac-spotlight-usage",
        parserVersion: "1",
        mappingVersion: "mac-spotlight-usage-v1",
      },
      spotlightUsage: {
        tool: "mac_apt-spotlight",
        itemId: clip(itemId, MAX_FIELD_LEN),
        ...(parentIdRaw ? { parentId: clip(parentIdRaw, MAX_FIELD_LEN) } : {}),
        ...(displayNameRaw ? { displayName: clip(displayNameRaw, MAX_FIELD_LEN) } : {}),
        displayNameSource,
        pathStatus: pathRaw ? "resolved" : "not-exported",
        ...(pathRaw ? { path: clip(pathRaw, MAX_FIELD_LEN) } : {}),
        ...(useCount !== undefined ? { useCount } : {}),
        ...(lastUsedDate ? { lastUsedDate } : {}),
        ...(usedDatesRaw ? { usedDatesRaw: clip(usedDatesRaw, MAX_FIELD_LEN) } : {}),
        ...(downloadedDateRaw ? { downloadedDateRaw: clip(downloadedDateRaw, MAX_FIELD_LEN) } : {}),
        ...(whereFromsRaw ? { whereFromsRaw: clip(whereFromsRaw, MAX_FIELD_LEN) } : {}),
        ...(dateUpdated ? { dateUpdated } : {}),
        storeIdentity,
        storeIdentitySource,
        reportFingerprint,
        mappingVersion: "mac-spotlight-usage-v1",
        basis: SPOTLIGHT_USAGE_BASIS,
      },
    }),
  };
}

export function parseMacSpotlightUsageCsv(
  text: string,
  opts: MacSpotlightUsageOptions = {},
): MacSpotlightUsageResult | null {
  const it = parseCsvRecords(text);
  const first = it.next();
  if (first.done) return null;
  const header = first.value;
  if (!isValidHeader(header)) return null;

  const { storeIdentity, storeIdentitySource } = deriveStoreIdentity(opts.sourceLabel);
  const reportFingerprint = createHash("sha256").update(text).digest("hex");

  const mapped: MappedEvent[] = [];
  let total = 0;
  let malformedRows = 0;
  let filteredNoSignalRows = 0;
  let rowsTruncated = false;
  let scanned = 0;

  for (const row of it) {
    if (scanned >= MAX_SPOTLIGHT_ROWS_SCANNED) {
      rowsTruncated = true;
      break;
    }
    scanned += 1;
    total += 1;
    if (row.length !== header.length) {
      malformedRows += 1;
      continue;
    }
    const event = mapRow(header, row, reportFingerprint, storeIdentity, storeIdentitySource);
    if (event === "no-signal") {
      filteredNoSignalRows += 1;
      continue;
    }
    if (!event) {
      malformedRows += 1;
      continue;
    }
    mapped.push(event);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_SPOTLIGHT_ROWS_SCANNED,
  });

  return {
    events,
    iocs: [],
    total,
    kept: events.length,
    dropped: malformedRows,
    groups,
    format: "MacAptSpotlightCsv",
    malformedRows,
    filteredNoSignalRows,
    rowsTruncated,
  };
}
