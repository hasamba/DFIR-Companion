import type { CaseStore } from "../../../../storage/caseStore.js";
import type { ForensicEvent, Severity } from "../../../stateTypes.js";
import { WATSON_MARKER } from "../../../timeline/watsonItems.js";
import { readPasteText } from "../roundContext.js";
import type { WatsonPaste } from "../types.js";

// A line of a stored paste that a Watson finding cites becomes a forensic event when the finding is
// applied, so the citation points at a real row in the timeline. The pasted text is adversary
// controlled: it is stored verbatim (whitespace collapsed, length capped) and escaped on render.

export const PASTE_LINE_DESCRIPTION_MAX = 2000;

const ISO = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/;
const SPACED = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/;

export const pasteLineEventId = (pasteId: string, line: number): string => `ev-watson-${pasteId}-${line}`;

/** The first ISO-8601 or `YYYY-MM-DD HH:MM:SS` time in the line, as ISO (UTC when it names no zone). */
export function lineTimestamp(text: string): string {
  const found = ISO.exec(text)?.[0] ?? SPACED.exec(text)?.[0];
  if (!found) return "";
  const iso = found.replace(" ", "T");
  const zoned = /(?:Z|[+-]\d{2}:?\d{2})$/.test(iso) ? iso : `${iso}Z`;
  const ms = Date.parse(zoned);
  return Number.isNaN(ms) ? "" : new Date(ms).toISOString();
}

export function pasteLineEvent(
  paste: WatsonPaste,
  line: number,
  text: string,
  severity: Severity,
  findingId: string,
  promotedAt: string = new Date().toISOString(),
): ForensicEvent {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return {
    id: pasteLineEventId(paste.id, line),
    timestamp: lineTimestamp(collapsed),
    description: `Pasted ${paste.filename} line ${line}: ${collapsed}`.slice(0, PASTE_LINE_DESCRIPTION_MAX),
    severity,
    mitreTechniques: [],
    relatedFindingIds: [findingId],
    sourceScreenshots: [],
    promotedAt,
    provenance: [WATSON_MARKER],
  };
}

/** The requested lines (1-based) of a stored paste. A line the paste does not have is not in the map. */
export async function readPasteLines(
  cases: CaseStore,
  caseId: string,
  paste: WatsonPaste,
  lines: readonly number[],
): Promise<Map<number, string>> {
  const all = (await readPasteText(cases, caseId, paste)).split(/\r?\n/);
  const out = new Map<number, string>();
  for (const n of lines) {
    if (Number.isInteger(n) && n >= 1 && n <= all.length) out.set(n, all[n - 1]);
  }
  return out;
}
