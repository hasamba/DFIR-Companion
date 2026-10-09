// Concatenated top-level JSON values as one record stream — moved out of siemImport.ts (which the
// file-size ledger freezes) so the Sysmon mapper could carry the process GUID and the structured
// action the sequence join reads (#987). Re-exported from siemImport.ts for its callers.

// One forward scan for the next depth-0 value at or after `from`, with fresh state.
// "ok" — a balanced value parsed; "fail" — a value opened at `start` but never closed before EOF
// (`end` = -1), or closed at `end` and failed JSON.parse; "none" — no further value opens.
type ScanResult =
  | { kind: "ok"; value: unknown; end: number }
  | { kind: "fail"; start: number; end: number }
  | { kind: "none" };

function scanValue(text: string, from: number): ScanResult {
  let depth = 0,
    start = -1,
    inStr = false,
    esc = false;
  for (let i = from; i < text.length; i++) {
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
    } else if ((ch === "}" || ch === "]") && depth > 0 && --depth === 0) {
      try {
        return { kind: "ok", value: JSON.parse(text.slice(start, i + 1)), end: i + 1 };
      } catch {
        return { kind: "fail", start, end: i + 1 };
      }
    }
  }
  return depth > 0 ? { kind: "fail", start, end: -1 } : { kind: "none" };
}

// Index of the next `{`/`[` at column 0 (start of text, or right after a newline) at or after
// `from`, or -1. Column 0 only: pretty-printers indent nested values, so resyncing here does not
// promote a nested object to a spurious top-level record.
function nextColumnZeroOpener(text: string, from: number): number {
  for (let i = from; i < text.length; i++) {
    const ch = text[i];
    if ((ch === "{" || ch === "[") && (i === 0 || text[i - 1] === "\n" || text[i - 1] === "\r")) {
      return i;
    }
  }
  return -1;
}

// Parse a stream of CONCATENATED top-level JSON values (objects/arrays), tolerating pretty-
// printing and any separators (commas / whitespace / newlines) between them. This is the shape
// Hayabusa's `json-timeline` emits by default: many multi-line `{ … }` objects with NO array
// wrapper and NO commas — which is neither a single JSON document nor NDJSON, so both the
// whole-file parse and the line-by-line NDJSON parse miss it. Walks the string tracking brace/
// bracket depth (ignoring braces inside string literals) and JSON.parses each depth-0 value.
// Pure and non-throwing. A malformed chunk is skipped without losing the rest of the stream
// (#2064): when a value never closes before EOF (truncated record, stray brace, unterminated
// string), or closes but fails to parse, the scan resyncs at the next column-0 `{`/`[` after the
// chunk's start with fresh state; a closed chunk with no such opener inside it resumes at its end.
// Valid input never takes the failure path, so its output is unchanged. Worst case O(k·n) for k
// unterminated openers.
export function parseConcatenatedJson(text: string): unknown[] {
  const out: unknown[] = [];
  let pos = 0;
  while (pos < text.length) {
    const r = scanValue(text, pos);
    if (r.kind === "none") break;
    if (r.kind === "ok") {
      out.push(r.value);
      pos = r.end;
      continue;
    }
    const next = nextColumnZeroOpener(text, r.start + 1);
    if (r.end !== -1 && (next === -1 || next >= r.end)) pos = r.end;
    else if (next !== -1) pos = next;
    else break;
  }
  return out;
}
