import { parseCsv } from "./csvImport.js";

// A Velociraptor CSV export (Elastic Discover "Download CSV") as flat rows. Lifted out of
// velociraptorImport.ts unchanged (#1736) to make room under its file-size ledger.

type Row = Record<string, unknown>;

// Parse a CSV export (Elastic Discover "Download CSV") into flat row objects keyed by header,
// dropping Kibana's "-" empty-cell placeholder. Returns null when it doesn't look tabular.
export function csvToRows(text: string): { rows: Row[]; format: string } | null {
  const { headers, rows } = parseCsv(text);
  if (headers.length < 2 || rows.length === 0) return null;
  const out: Row[] = rows.map((cells) => {
    const o: Row = {};
    headers.forEach((h, i) => {
      const v = cells[i];
      if (v != null && v !== "" && v !== "-") o[h] = v;
    });
    return o;
  });
  return { rows: out, format: "csv" };
}
