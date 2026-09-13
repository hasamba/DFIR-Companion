// Concatenated top-level JSON values as one record stream — moved out of siemImport.ts (which the
// file-size ledger freezes) so the Sysmon mapper could carry the process GUID and the structured
// action the sequence join reads (#987). Re-exported from siemImport.ts for its callers.

// Parse a stream of CONCATENATED top-level JSON values (objects/arrays), tolerating pretty-
// printing and any separators (commas / whitespace / newlines) between them. This is the shape
// Hayabusa's `json-timeline` emits by default: many multi-line `{ … }` objects with NO array
// wrapper and NO commas — which is neither a single JSON document nor NDJSON, so both the
// whole-file parse and the line-by-line NDJSON parse miss it. Walks the string tracking brace/
// bracket depth (ignoring braces inside string literals) and JSON.parses each depth-0 value.
// Pure; malformed chunks are skipped rather than throwing.
export function parseConcatenatedJson(text: string): unknown[] {
  const out: unknown[] = [];
  let depth = 0,
    start = -1,
    inStr = false,
    esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === "{" || ch === "[") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}" || ch === "]") {
      if (depth > 0 && --depth === 0 && start !== -1) {
        try {
          out.push(JSON.parse(text.slice(start, i + 1)));
        } catch {
          /* skip malformed chunk */
        }
        start = -1;
      }
    }
  }
  return out;
}
