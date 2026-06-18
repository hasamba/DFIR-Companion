// Pure helpers for importing a CSV export (e.g. a Velociraptor artifact result set)
// as evidence: parse it, then batch the rows so each batch can be sent to the model
// for forensic-event extraction (the same delta the screenshot path produces).

export interface ParsedCsv {
  headers: string[];
  rows: string[][];
}

// Minimal RFC-4180-ish parser: handles quoted fields, embedded commas/newlines, and
// "" escaped quotes. Tolerant of CRLF line endings and a trailing newline. Good
// enough for tool exports (Velociraptor, Excel, pandas) without a parser dependency.
//
// Streaming generator: yields one record (string[]) at a time WITHOUT building the
// whole file into a 2D array first. Critical for huge exports (e.g. a 400 MB Plaso
// super-timeline) — a caller that maps+aggregates each record as it streams keeps
// memory bounded by the distinct-key set, not the (millions of) row count. Fully-empty
// records (a blank trailing line → [""]) are skipped so the first yield is the header.
export function* parseCsvRecords(text: string): Generator<string[]> {
  let field = "";
  let record: string[] = [];
  let inQuotes = false;
  let started = false; // did the current record receive any field/char?

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } // escaped quote
        else inQuotes = false;
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') { inQuotes = true; started = true; continue; }
    if (ch === ",") { record.push(field); field = ""; started = true; continue; }
    if (ch === "\r") { continue; }
    if (ch === "\n") {
      record.push(field); field = "";
      if (!(record.length === 1 && record[0] === "")) yield record; // skip fully-empty
      record = []; started = false;
      continue;
    }
    field += ch;
    started = true;
  }
  // Flush a final record that wasn't newline-terminated.
  if (started || field.length > 0) {
    record.push(field);
    if (!(record.length === 1 && record[0] === "")) yield record;
  }
}

export function parseCsv(text: string): ParsedCsv {
  let headers: string[] = [];
  const rows: string[][] = [];
  let first = true;
  for (const rec of parseCsvRecords(text)) {
    if (first) { headers = rec; first = false; }
    else rows.push(rec);
  }
  return { headers, rows };
}

// Streaming CSV records from a line source (e.g. node:readline over a file read stream) — for
// files too large to ever hold as a single JS string (a 555 MB Plaso super-timeline EXCEEDS V8's
// ~512 MB max string length, so readFile(utf8) throws "Invalid string length" outright). Physical
// lines are joined into one logical record until the running double-quote count is balanced (a
// quoted field — e.g. a Plaso `message` — may contain embedded newlines spanning several lines),
// then parsed. A per-record byte cap force-flushes so a single stray/unbalanced quote can't swallow
// the rest of the file into one ever-growing field (the OOM trap of a naive char-streaming parser).
export async function* parseCsvRecordsFromLines(
  lines: AsyncIterable<string>,
  opts: { maxRecordChars?: number } = {},
): AsyncGenerator<string[]> {
  const maxRecord = opts.maxRecordChars ?? 8 * 1024 * 1024;
  let buf = "";
  let quotes = 0;
  let have = false;
  for await (const line of lines) {
    buf = have ? `${buf}\n${line}` : line;
    have = true;
    for (let i = 0; i < line.length; i++) if (line[i] === '"') quotes++;
    if (quotes % 2 === 0 || buf.length > maxRecord) {
      // parseCsvRecords correctly treats a \n inside an open quote as part of the field, so the
      // re-joined buffer reproduces the original logical record exactly (normally exactly one).
      for (const rec of parseCsvRecords(buf)) yield rec;
      buf = ""; quotes = 0; have = false;
    }
  }
  if (have) for (const rec of parseCsvRecords(buf)) yield rec;
}

export function chunk<T>(items: readonly T[], size: number): T[][] {
  if (size <= 0) throw new Error("chunk size must be > 0");
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

// Re-serialize a header + a batch of rows to compact CSV text for the model prompt.
export function chunkToCsvText(headers: string[], rows: string[][]): string {
  const esc = (v: string): string => (/[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  const head = headers.map(esc).join(",");
  const body = rows.map((r) => r.map(esc).join(",")).join("\n");
  return body.length > 0 ? `${head}\n${body}` : head;
}
