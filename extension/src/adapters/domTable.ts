// Pure DOM-table → rows conversion (the issue's "Table Parsing" fallback for when a tool exposes no
// clean JSON API). The browser-only part — reading <table> cells into a string matrix — lives in
// artifactCapture.ts; this module takes that already-extracted matrix so the mapping logic is
// unit-testable without a DOM.

/**
 * Convert a header row + body matrix into row objects. Empty / whitespace headers get a positional
 * fallback name (`col1`, `col2`, …). Ragged rows are tolerated (missing cells → ""). Returns [] when
 * there are no body rows.
 */
export function matrixToRows(headers: string[], rows: string[][]): Record<string, string>[] {
  const names = normalizeHeaders(headers, rows);
  return rows.map((cells) => {
    const obj: Record<string, string> = {};
    names.forEach((name, i) => { obj[name] = (cells[i] ?? "").trim(); });
    return obj;
  });
}

// Build unique, non-empty column names. When the header row is missing/short, synthesize names from
// the widest body row so no cells are dropped.
function normalizeHeaders(headers: string[], rows: string[][]): string[] {
  const width = Math.max(headers.length, ...rows.map((r) => r.length), 0);
  const used = new Set<string>();
  const names: string[] = [];
  for (let i = 0; i < width; i++) {
    let base = (headers[i] ?? "").trim() || `col${i + 1}`;
    let name = base;
    let n = 2;
    while (used.has(name)) name = `${base}_${n++}`; // de-dup repeated headers
    used.add(name);
    names.push(name);
  }
  return names;
}
