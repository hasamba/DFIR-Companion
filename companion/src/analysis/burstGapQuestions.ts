// A Key Question for each burst group whose prompt row hid distinct command lines (#2681).
//
// synthGroup.ts folds a detection burst into one prompt row, and synthGroupMembers.ts spells out at most
// 12 member commands that differ; the rest are counted as "+N more" with no ids. On scenario 029 the
// hidden lines held every post-exploitation step, three syntheses named only the shown ones, and Watson
// Auto never read the rest, because nothing on the board pointed at them.
//
// So the synthesis fold asks: one pinned, system-made Key Question per group that hides lines, with a
// stable id from the group's representative, pointing at the hidden event ids. Watson Auto works open
// Key Questions, and reads the rows with a lookup by event id from the FORENSIC timeline — this module
// reads only the events it is handed by id and never the super-timeline.
//
// Lifecycle, re-derived on every synthesis: answered only when live, non-automatic findings cite EVERY
// hidden id, not just the listed ones (partial when they cite some). The question lists at most
// BURST_GAP_LISTED_IDS ids, the ones still uncited, so each run hands Watson the next batch. Only the
// counts and that list are stored: the full id set is re-derived from the run's grouping, so the
// state stays small however big the burst. Dropped when the group no longer hides lines; at most
// MAX_BURST_GAP_QUESTIONS per case, largest gap first, questions already asked keeping their seat. An
// answer the analyst applied from Watson is never overwritten. Pure.

import { AUTO_FINDING_ID_PREFIX } from "./responseSchema.js";
import type { BurstCoverageGap, Finding, ForensicEvent, InvestigationQuestion } from "./stateTypes.js";
import { groupMemberLines } from "./synthGroupMembers.js";
import { isProtectedWatson } from "./timeline/watsonQuestions.js";

/** Id prefix of a burst-gap question; the representative event id follows. */
export const BURST_GAP_ID_PREFIX = "sys-burst-";
/** How many burst-gap questions one case carries at most, so a noisy case does not flood the board. */
export const MAX_BURST_GAP_QUESTIONS = 3;
/** Hidden ids listed per question: Watson's lookup limit (WATSON_LOOKUP_LIMITS.eventIds). */
export const BURST_GAP_LISTED_IDS = 50;
// Host and image names come from the evidence (adversary-controlled): one line, short.
const NAME_CHARS = 60;

export interface BurstGapInput {
  /** The prompt's grouped rows: representative id → every member id. Undefined → no change at all. */
  membersOf: ReadonlyMap<string, readonly string[]> | undefined;
  /** Forensic-timeline events, looked up by id only. */
  events: readonly ForensicEvent[];
  /** The case's findings after the merge: their own citations decide whether the gap is closed. */
  findings: readonly Pick<Finding, "id" | "status" | "relatedEventIds">[];
}

const gapId = (representativeId: string): string => `${BURST_GAP_ID_PREFIX}${representativeId}`;
const isGapQuestion = (q: InvestigationQuestion): boolean => q.id.startsWith(BURST_GAP_ID_PREFIX);

function cleanName(raw: string | undefined): string {
  return (raw ?? "")
    .replace(/[\u0000-\u001f\u007f<>`|]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, NAME_CHARS);
}

function imageName(e: ForensicEvent): string {
  const path = (e.path ?? "").trim();
  return cleanName(path ? path.split(/[\\/]/).pop() : e.processName);
}

interface Gap {
  representativeId: string;
  memberCount: number;
  /** Every hidden distinct line's event id, unlisted ones included. */
  hiddenIds: string[];
  host: string;
  image: string;
}

function gapsOf(input: BurstGapInput, membersOf: ReadonlyMap<string, readonly string[]>): Gap[] {
  const byId = new Map(input.events.map((e) => [e.id, e] as const));
  const gaps: Gap[] = [];
  for (const [representativeId, ids] of membersOf) {
    const members = ids.map((id) => byId.get(id)).filter((e): e is ForensicEvent => !!e);
    if (members[0]?.id !== representativeId) continue; // the representative must lead its burst
    const { hiddenIds } = groupMemberLines(members);
    if (!hiddenIds.length) continue;
    gaps.push({
      representativeId,
      memberCount: members.length,
      hiddenIds,
      host: cleanName(members[0].asset),
      image: imageName(members[0]),
    });
  }
  return gaps.sort(
    (a, b) => b.hiddenIds.length - a.hiddenIds.length || a.representativeId.localeCompare(b.representativeId),
  );
}

/** Which gaps get a question: the ones already asked first, then the largest new ones, up to the cap. */
function selectGaps(gaps: Gap[], askedIds: ReadonlySet<string>): Gap[] {
  const asked = gaps.filter((g) => askedIds.has(gapId(g.representativeId)));
  const fresh = gaps.filter((g) => !askedIds.has(gapId(g.representativeId)));
  return [...asked, ...fresh].slice(0, MAX_BURST_GAP_QUESTIONS);
}

function questionText(g: Gap): string {
  const from = g.image ? ` from ${g.image}` : "";
  const on = g.host ? ` on ${g.host}` : "";
  const n = g.hiddenIds.length;
  const lines = n === 1 ? "1 distinct command line" : `${n} distinct command lines`;
  return `A grouped burst of ${g.memberCount} events${from}${on} hid ${lines} that synthesis counted but never read. What did they run?`;
}

/** Which hidden ids live findings cite themselves, and which findings cite them. */
interface Coverage {
  uncited: string[];
  coveredCount: number;
  covering: string[];
}

// The live findings that cite each hidden id themselves — an automatic backfill finding or a dismissed
// one is not a reading of the line, and a citation of the representative alone covers nothing here.
function coverageOf(g: Gap, findings: BurstGapInput["findings"]): Coverage {
  const readers = findings.filter(
    (f) => !f.id.startsWith(AUTO_FINDING_ID_PREFIX) && f.status !== "dismissed",
  );
  const hidden = new Set(g.hiddenIds);
  const covering = new Set<string>();
  const cited = new Set<string>();
  for (const f of readers)
    for (const id of f.relatedEventIds ?? [])
      if (hidden.has(id)) {
        cited.add(id);
        covering.add(f.id);
      }
  return {
    uncited: g.hiddenIds.filter((id) => !cited.has(id)),
    coveredCount: cited.size,
    covering: [...covering],
  };
}

function pointerText(g: Gap, c: Coverage): string {
  if (!c.uncited.length) return "Findings cite every hidden line of this burst.";
  const listed = Math.min(c.uncited.length, BURST_GAP_LISTED_IDS);
  const total = g.hiddenIds.length;
  const part =
    c.uncited.length > listed
      ? ` (the first ${listed} of ${c.uncited.length} still uncited, of ${total} hidden)`
      : c.coveredCount
        ? ` (the ${listed} of ${total} hidden still uncited)`
        : "";
  return `Read these forensic-timeline events by id${part}: ${c.uncited.slice(0, listed).join(", ")}`;
}

function answerState(
  g: Gap,
  c: Coverage,
): Pick<InvestigationQuestion, "status" | "answer"> & { relatedFindingIds?: string[] } {
  const total = g.hiddenIds.length;
  if (!c.coveredCount) return { status: "unknown", answer: "" };
  const ids = c.covering;
  if (!c.uncited.length)
    return {
      status: "answered",
      answer: `Findings ${ids.join(", ")} cite every hidden line.`,
      relatedFindingIds: ids,
    };
  return {
    status: "partial",
    answer: `Findings ${ids.join(", ")} cite ${c.coveredCount} of ${total} hidden lines.`,
    relatedFindingIds: ids,
  };
}

function gapField(g: Gap, c: Coverage): BurstCoverageGap {
  return {
    kind: "burst-hidden-lines",
    representativeId: g.representativeId,
    memberCount: g.memberCount,
    hiddenCount: g.hiddenIds.length,
    coveredCount: c.coveredCount,
    hiddenEventIds: c.uncited.slice(0, BURST_GAP_LISTED_IDS),
  };
}

function buildQuestion(
  g: Gap,
  existing: InvestigationQuestion | undefined,
  findings: BurstGapInput["findings"],
): InvestigationQuestion {
  const c = coverageOf(g, findings);
  // An answer the analyst applied from Watson stands; only the gap data is refreshed.
  if (existing && isProtectedWatson(existing)) return { ...existing, coverageGap: gapField(g, c) };
  return {
    id: gapId(g.representativeId),
    question: questionText(g),
    pointer: pointerText(g, c),
    ...answerState(g, c),
    pinned: true,
    coverageGap: gapField(g, c),
    // An unanswered question Watson touched keeps Watson's mark, so no merge drops it.
    ...(existing?.author === "watson" ? { author: "watson" as const } : {}),
  };
}

/**
 * The key questions with one burst-gap question per group that hides lines. Questions that are not
 * burst-gap questions pass through untouched and in order; a new gap question is appended.
 */
export function applyBurstGapQuestions(
  questions: readonly InvestigationQuestion[],
  input: BurstGapInput,
): InvestigationQuestion[] {
  if (!input.membersOf) return [...questions];
  const asked = new Set(questions.filter(isGapQuestion).map((q) => q.id));
  const chosen = new Map(
    selectGaps(gapsOf(input, input.membersOf), asked).map((g) => [gapId(g.representativeId), g] as const),
  );
  const out: InvestigationQuestion[] = [];
  for (const q of questions) {
    if (!isGapQuestion(q)) out.push(q);
    else {
      const g = chosen.get(q.id);
      if (!g) continue; // the group no longer hides lines (or lost its seat): drop the question
      out.push(buildQuestion(g, q, input.findings));
      chosen.delete(q.id);
    }
  }
  for (const g of chosen.values()) out.push(buildQuestion(g, undefined, input.findings));
  return out;
}
