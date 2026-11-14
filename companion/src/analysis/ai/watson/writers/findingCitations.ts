import { rewriteRows } from "../../../forensicRowRewrite.js";
import type { Finding, ForensicEvent } from "../../../stateTypes.js";
import { WATSON_MARKER } from "../../../timeline/watsonItems.js";
import type { WatsonFindingProposal, WatsonPaste } from "../types.js";
import { pasteLineEvent, pasteLineEventId, readPasteLines } from "./pasteLineEvents.js";
import type { WriterDeps } from "./writerTypes.js";

// What a Watson finding cites, re-checked at apply time: forensic events that still exist and paste
// lines that still read. Plus the row links: each cited event lists the finding in relatedFindingIds.

type PasteLine = { pasteId: string; line: number };

export interface LiveCitations {
  /** Cited forensic events that exist now (paste-line events not included). */
  eventIds: string[];
  /** Cited paste lines that still read. */
  pasteLines: PasteLine[];
  /** One event per live paste line, carrying the finding's severity and the apply's stamp. */
  pasteEvents: ForensicEvent[];
}

const unique = (ids: readonly string[]): string[] => [...new Set(ids)];

const sortedIds = (ids: readonly string[] | undefined): string => JSON.stringify([...(ids ?? [])].sort());

/** The fields an analyst or a synthesis would change: what undo and finding_update compare. */
export function sameFinding(a: Finding, b: Finding): boolean {
  return (
    a.title === b.title &&
    a.severity === b.severity &&
    a.description === b.description &&
    a.status === b.status &&
    sortedIds(a.relatedEventIds) === sortedIds(b.relatedEventIds)
  );
}

/** Lines of one paste that still read; none when the paste or the case store is gone. */
async function liveLines(deps: WriterDeps, caseId: string, paste: WatsonPaste | undefined, lines: number[]) {
  if (!paste || !deps.cases) return new Map<number, string>();
  try {
    return await readPasteLines(deps.cases, caseId, paste, lines);
  } catch {
    return new Map<number, string>(); // removed or unreadable file: those citations are not live
  }
}

async function livePasteEvents(
  deps: WriterDeps,
  caseId: string,
  p: WatsonFindingProposal,
  promotedAt: string,
): Promise<{ pasteLines: PasteLine[]; pasteEvents: ForensicEvent[] }> {
  const cited = p.after.citedPasteLines ?? [];
  if (!cited.length) return { pasteLines: [], pasteEvents: [] };
  const { pastes } = await deps.chatStore.load(caseId);
  const pasteLines: PasteLine[] = [];
  const pasteEvents: ForensicEvent[] = [];
  for (const pasteId of unique(cited.map((c) => c.pasteId))) {
    const paste = pastes.find((x) => x.id === pasteId);
    const wanted = cited.filter((c) => c.pasteId === pasteId).map((c) => c.line);
    const read = await liveLines(deps, caseId, paste, wanted);
    for (const [line, text] of read) {
      const id = pasteLineEventId(pasteId, line);
      if (pasteEvents.some((e) => e.id === id)) continue;
      const drafted = p.pasteLineEvents.find((e) => e.id === id);
      const built = drafted ?? pasteLineEvent(paste as WatsonPaste, line, text, p.after.severity, p.targetId);
      pasteLines.push({ pasteId, line });
      pasteEvents.push({
        ...built,
        severity: p.after.severity,
        relatedFindingIds: [p.targetId],
        promotedAt,
        provenance: unique([...(built.provenance ?? []), WATSON_MARKER]),
      });
    }
  }
  return { pasteLines, pasteEvents };
}

/** Re-check every citation of the draft against the case as it is now. */
export async function liveCitations(
  deps: WriterDeps,
  caseId: string,
  p: WatsonFindingProposal,
  promotedAt: string,
): Promise<LiveCitations> {
  const { pasteLines, pasteEvents } = await livePasteEvents(deps, caseId, p, promotedAt);
  const pasteIds = new Set(pasteEvents.map((e) => e.id));
  const drafted = unique(p.after.relatedEventIds ?? []).filter((id) => !pasteIds.has(id));
  const found = await deps.stateStore.hasForensicEventIds(caseId, drafted);
  return { eventIds: drafted.filter((id) => found.has(id)), pasteLines, pasteEvents };
}

/** Add the finding to `add` rows' relatedFindingIds and take it off `remove` rows. Missing rows are skipped. */
export async function relink(
  deps: WriterDeps,
  caseId: string,
  findingId: string,
  add: readonly string[],
  remove: readonly string[],
): Promise<void> {
  const ids = unique([...add, ...remove]);
  if (!ids.length) return;
  const adding = new Set(add);
  const removing = new Set(remove);
  const rows = await deps.stateStore.forensicRowsById(caseId, ids);
  await rewriteRows(deps.stateStore, caseId, rows, (e) => {
    const linked = e.relatedFindingIds ?? [];
    const has = linked.includes(findingId);
    if (adding.has(e.id) && !has) return { ...e, relatedFindingIds: [...linked, findingId] };
    if (removing.has(e.id) && has) return { ...e, relatedFindingIds: linked.filter((x) => x !== findingId) };
    return e;
  });
}
