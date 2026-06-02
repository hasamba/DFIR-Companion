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
export function parseCsv(text: string): ParsedCsv {
  const records: string[][] = [];
  let field = "";
  let record: string[] = [];
  let inQuotes = false;
  let started = false; // did the current record receive any field/char?

  const endField = (): void => { record.push(field); field = ""; started = true; };
  const endRecord = (): void => { records.push(record); record = []; started = false; };

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
    if (ch === ",") { endField(); continue; }
    if (ch === "\r") { continue; }
    if (ch === "\n") { endField(); endRecord(); continue; }
    field += ch;
    started = true;
  }
  // Flush a final record that wasn't newline-terminated.
  if (started || field.length > 0) { endField(); endRecord(); }

  // Drop fully-empty records (e.g. a blank trailing line → [""]).
  const nonEmpty = records.filter((r) => !(r.length === 1 && r[0] === ""));
  const headers = nonEmpty.length > 0 ? nonEmpty[0] : [];
  const rows = nonEmpty.slice(1);
  return { headers, rows };
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
