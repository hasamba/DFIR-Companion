// What a memory export's SHAPE establishes, and nothing more (#933 item 12).
//
// A Volatility export with a header and no rows, a `[]`, or an empty array under a plugin-map key
// used to be refused with a 400 ("no parseable memory output"), so "malfind found nothing" and
// "malfind never ran" were both silent. Both now land as one Low row that says exactly what the
// export holds — zero rows under a label — and exactly what it does not establish: that the plugin
// completed, or which pages it covered. The quick renderer writes its header before the plugin
// iterates, `[]` is an empty tree, and a filename or a map key is a label the uploader chose, so
// none of those is a completion claim. "Completed with no match" needs a run envelope (command,
// exit status, separate stderr) that the upload format does not carry; that is a separate spec.
//
// Diagnostic-looking lines (`Unsatisfied requirement …`, `Traceback`, `Volatility was unable to
// read a requested page …`) are uploader-controlled text: an artifact value can spell them, and a
// verbose startup traceback can describe an unrelated optional import while the plugin succeeds.
// They are shown, neutralised, in the import NOTE as unverified text — never as grounds for a row,
// a severity, or an absence claim.

import type { MappedEvent } from "./siemImport.js";
import { breakHashRuns, keyDigest, showToken } from "./recordIdentity.js";

const DIAGNOSTIC_RE =
  /^(?:Unsatisfied requirement\b|Unable to validate the plugin requirements\b|A symbol table requirement was not fulfilled\b|Traceback \(most recent call last\)|Volatility was unable to read a requested page\b|[A-Za-z_][\w.]*(?:Error|Exception):\s)/;

const SHOWN_MAX = 160;

function shown(value: string, max = SHOWN_MAX): string {
  const t = breakHashRuns(showToken(value ?? ""));
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

/**
 * Lines OUTSIDE any table (no TAB, so never a data row of the grid renderer) that look like
 * Volatility diagnostics. Unverified text, by construction.
 */
export function diagnosticLines(text: string): string[] {
  const out: string[] = [];
  for (const raw of (text ?? "").split(/\r\n|\r|\n/)) {
    if (raw.includes("\t")) continue;
    const line = raw.trim();
    if (line && DIAGNOSTIC_RE.test(line)) out.push(line);
    if (out.length >= 50) break;
  }
  return out;
}

/** Every zero-row label as a row — Low, undated, no indicator. */
export function exportShapeEvents(format: string, empty: readonly string[], tool: string): MappedEvent[] {
  const source = tool || "Volatility";
  if (format === "volatility2-text") {
    return [
      {
        timestamp: "",
        description:
          "Memory export not read [Volatility 2 text layout] — its profile-based column layout is not read; re-run under Volatility 3 (symbol tables) or export JSON. This is a fact about the importer, not about the host. [undated: the export carries no time]",
        severity: "Low",
        mitre: [],
        aggKey: "mem|export|vol2",
        sources: [source],
      },
    ];
  }
  const by = format === "volatility-map" ? "claimed by the export key" : "claimed by the export name";
  return empty.map((label) => ({
    timestamp: "",
    description:
      `Memory export holds zero rows [label: ${label ? `${shown(label, 80)} (${by})` : "none"}] [tool: as labelled]` +
      " — completion of the search and the pages it covered are not established by this export; a row absent here is not a row absent from the image. [undated: the export carries no time]",
    severity: "Low",
    mitre: [],
    aggKey: `mem|export|zero-rows|${keyDigest(label)}`,
    sources: [source],
  }));
}

/** The import note's statement about the export's shape. Never grades. */
export function exportShapeNote(text: string, format: string, empty: readonly string[], tables = 0): string {
  const parts: string[] = [];
  if (format === "volatility2-text") parts.push("Volatility 2 layout not read");
  // A Volatility banner with nothing tabular after it: not zero rows — no table at all.
  if (format === "volatility-text" && tables === 0 && empty.length === 0) {
    parts.push("a Volatility banner with no table after it — nothing was read; completion not established");
  }
  for (const label of empty) {
    parts.push(`zero rows under label ${label ? shown(label, 80) : "none"} — completion not established`);
  }
  const diag = diagnosticLines(text);
  if (diag.length) {
    parts.push(
      `the export also carries ${diag.length} diagnostic-looking line(s) outside the table (unverified text): ${shown(diag[0])}`,
    );
  }
  return parts.join("; ");
}
