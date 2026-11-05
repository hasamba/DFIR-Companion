// The JSON reader the cloud importers share (#2302). It wraps extractRecords and repairs three
// faults real cloud exports carry, COUNTING each repair so the import note can disclose it:
//   - a UTF-8 byte-order mark (PowerShell's Out-File / Export-Csv on Windows PowerShell 5.1);
//   - concatenated documents, `[…][…]` (DFIR-O365RC appends a second array to an hourly file);
//   - text that is not JSON before, between or after the documents (a truncated tail, a log line).
// A valid document, or genuine NDJSON, is read exactly as extractRecords reads it. The repair scan
// is the concatenated-JSON scanner extractRecords already falls back to — one scanner, not two.

import { extractRecords, isObject } from "./siemImport.js";
import { scanConcatenatedJson } from "./concatenatedJson.js";

type Row = Record<string, unknown>;

export interface JsonRepairs {
  /** 1 when a leading UTF-8 byte-order mark was removed. */
  bomStripped: number;
  /** Seams between concatenated top-level documents that were joined (`][` is one). */
  documentsJoined: number;
  /** Stretches of text that were not JSON and were skipped (trailing garbage, a broken chunk). */
  garbageSkipped: number;
}

export interface TolerantRecords {
  records: Row[];
  format: string;
  repairs: JsonRepairs;
}

const BOM = "\uFEFF";

export function noRepairs(bomStripped = 0): JsonRepairs {
  return { bomStripped, documentsJoined: 0, garbageSkipped: 0 };
}

/** Strip a leading byte-order mark, reporting whether there was one. */
export function stripBom(text: string): { body: string; bomStripped: number } {
  return text.startsWith(BOM) ? { body: text.slice(1), bomStripped: 1 } : { body: text, bomStripped: 0 };
}

function firstLineIsJson(body: string): boolean {
  const first = body.trim().split(/\r\n|\r|\n/, 1)[0] ?? "";
  try {
    return isObject(JSON.parse(first));
  } catch {
    return false;
  }
}

// Each recovered document is unwrapped by extractRecords itself, so a `{ Records: [...] }` or
// `{ value: [...] }` wrapper (and every other container it knows) yields its records exactly as it
// would in a clean file. Re-serializing costs a second parse, paid only on this repair path.
function recordsOf(value: unknown): Row[] {
  return extractRecords(JSON.stringify(value)).records;
}

function nonEmptyLines(body: string): number {
  let n = 0;
  for (const line of body.split(/\r\n|\r|\n/)) if (line.trim()) n++;
  return n;
}

// One JSON value per line. A line that does not parse is skipped by extractRecords — count it. When
// the lines are whole wrapped documents (single-line CloudTrail objects, `{"Records":[...]}`, run
// together or followed by a stray line), unwrap each one as a clean file would be: judged on the
// first line, so plain JSON lines are not re-serialized.
function readJsonLines(body: string, lines: Row[], bomStripped: number): TolerantRecords {
  const garbageSkipped = Math.max(0, nonEmptyLines(body) - lines.length);
  const wrapped = lines.length > 0 && extractRecords(JSON.stringify(lines[0])).format !== "single";
  const records = wrapped ? lines.flatMap(recordsOf) : lines;
  const documentsJoined = wrapped ? Math.max(0, lines.length - 1) : 0;
  return { records, format: "ndjson", repairs: { bomStripped, documentsJoined, garbageSkipped } };
}

/** Read JSON, JSON lines or concatenated JSON records, repairing and counting what was wrong. */
export function readTolerantJsonRecords(text: string): TolerantRecords {
  const { body, bomStripped } = stripBom(text);
  const base = extractRecords(body);
  if (base.format !== "ndjson" && base.format !== "concatenated-json") {
    return { ...base, repairs: noRepairs(bomStripped) };
  }
  if (base.format === "ndjson" && firstLineIsJson(body))
    return readJsonLines(body, base.records, bomStripped);
  // Not one document and not JSON lines: scan it whole. A pretty-printed array with a broken tail
  // would otherwise lose every record but the few lines that happen to parse on their own.
  const { values, skipped } = scanConcatenatedJson(body.trim());
  const records = values.flatMap(recordsOf);
  if (records.length === 0) return { ...base, repairs: noRepairs(bomStripped) };
  return {
    records,
    format: "concatenated-json",
    repairs: { bomStripped, documentsJoined: Math.max(0, values.length - 1), garbageSkipped: skipped },
  };
}

/** The repairs in words, e.g. for an empty-import detail; "" when nothing was repaired. */
export function describeJsonRepairs(repairs: JsonRepairs | undefined): string {
  if (!repairs) return "";
  const parts = [
    repairs.bomStripped ? "a UTF-8 byte-order mark removed" : "",
    repairs.documentsJoined ? `${repairs.documentsJoined} join(s) between concatenated JSON documents` : "",
    repairs.garbageSkipped
      ? `${repairs.garbageSkipped} unreadable stretch(es) of text skipped — any records in them were not imported`
      : "",
  ].filter(Boolean);
  return parts.length ? `file repaired on read: ${parts.join(", ")}` : "";
}

/** The import-note clause for a set of repairs ("; file repaired on read: …"); "" when none. */
export function jsonRepairNote(repairs: JsonRepairs | undefined): string {
  const text = describeJsonRepairs(repairs);
  return text ? `; ${text}` : "";
}
