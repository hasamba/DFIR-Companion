// One "JSON or CSV → records" entry for the cloud importers (#2302): the M365, cloud-activity and
// CloudTrail importers used to read JSON only (M365 had its own CSV branch), so a Log Analytics
// AzureActivity CSV or a CloudTrail console CSV reached no importer that could read it. JSON goes
// through the tolerant reader; anything else is read as a CSV table and each row is handed to the
// importer's own adapter, which renames columns into the shape its mapper already reads.

import { parseCsv } from "./csvImport.js";
import { getCI, str } from "./siemFieldPick.js";
import { readTolerantJsonRecords, stripBom, noRepairs, type TolerantRecords } from "./tolerantJson.js";

type Row = Record<string, unknown>;

function csvRows(text: string): Row[] {
  const { headers, rows } = parseCsv(text);
  if (!headers.length) return [];
  return rows.map((cols) => Object.fromEntries(headers.map((h, i) => [h.trim(), cols[i] ?? ""])));
}

/** Records from a cloud export: JSON (tolerant) when it opens with `{`/`[`, else CSV rows through `adapt`. */
export function readCloudRecords(text: string, adapt: (row: Row) => Row = (r) => r): TolerantRecords {
  const { body, bomStripped } = stripBom(text);
  const t = body.trim();
  if (!t) return { records: [], format: "empty", repairs: noRepairs(bomStripped) };
  if (t[0] === "{" || t[0] === "[") return readTolerantJsonRecords(text);
  return { records: csvRows(t).map(adapt), format: "csv", repairs: noRepairs(bomStripped) };
}

// ───────────────────────────── AWS CloudTrail console CSV ─────────────────────────────

function parseJson(v: unknown): unknown {
  const s = str(v).trim();
  if (!s || (s[0] !== "{" && s[0] !== "[")) return undefined;
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

/**
 * One row of the CloudTrail console "Event history" CSV as a CloudTrail record. When the download
 * carries the full event (a `CloudTrail event` column), that record is used as is. Otherwise it is
 * built from the columns alone: the CSV has no identity type, ARN, account or request parameters,
 * so what the importer can conclude from such a row is limited to name, source, user and address.
 */
export function cloudTrailConsoleRow(row: Row): Row {
  const full = parseJson(getCI(row, "CloudTrail event"));
  if (full && typeof full === "object" && !Array.isArray(full)) return full as Row;
  if (!str(getCI(row, "Event name"))) return row;
  const col = (k: string): string => str(getCI(row, k)).trim();
  const userName = col("User name");
  const accessKeyId = col("AWS access key");
  const resources = parseJson(getCI(row, "Resources"));
  return {
    eventID: col("Event ID"),
    eventTime: col("Event time"),
    eventName: col("Event name"),
    eventSource: col("Event source"),
    awsRegion: col("AWS region"),
    sourceIPAddress: col("Source IP address"),
    ...(col("Error code") ? { errorCode: col("Error code") } : {}),
    readOnly: /^true$/i.test(col("Read-only")),
    ...(userName || accessKeyId
      ? { userIdentity: { ...(userName ? { userName } : {}), ...(accessKeyId ? { accessKeyId } : {}) } }
      : {}),
    ...(Array.isArray(resources) ? { resources } : {}),
  };
}
