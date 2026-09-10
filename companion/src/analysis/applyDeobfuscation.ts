// Scan a case's forensic timeline for obfuscated command lines, decode them, extract IOCs
// from the decoded payload, and attach the result to each event as `event.deobfuscated`.
// Pure: returns a new state, never mutates.
//
// Events already carrying `deobfuscated` are not re-processed (idempotent).
// The extracted IOCs are added to state.iocs (deduped by value) and their canonical
// ids are stored in the event's deobfuscated.iocs array.

import type { InvestigationState, ForensicEvent, IOC } from "./stateTypes.js";
import { deobfuscateText, extractIocsFromText } from "./deobfuscate.js";
import { decodeLayers, DECODER_VERSION } from "./deobfuscateLayers.js";
import { SEVERITY_RANK } from "./forensicGate.js";

function padIocId(n: number): string {
  return `i${String(n).padStart(3, "0")}`;
}

function nextIocSeq(iocs: readonly IOC[]): number {
  let max = 0;
  for (const i of iocs) {
    const m = /^i(\d+)$/.exec(i.id);
    if (m) max = Math.max(max, parseInt(m[1], 10));
  }
  return max + 1;
}

export interface DeobfuscationApplyResult {
  state: InvestigationState;
  deobfuscated: number; // events decoded this run
  newIocs: number; // net-new IOCs added from decoded content
  reanalyzed: number; // events re-decoded because their stored result predated this decoder
}

/**
 * Grades a decoded payload. INJECTED rather than imported: the behaviour rules live in the detect
 * domain and this pass lives in the privacy domain, and that edge is not one the module map allows.
 * The composition layer, which may import both, supplies it.
 */
export type DerivedTextGrader = (
  text: string,
) => { weight: "strong" | "weak" | null; mitre: string[] } | null;

export interface DeobfuscationApplyOptions {
  // Re-decode events whose stored result came from an OLDER decoder (#909 item 2).
  //
  // Without this the pass is purely idempotent: an event that already carries a `deobfuscated`
  // block is skipped forever, so improving the decoder helps only cases imported afterwards and
  // every existing case keeps its single-layer result. That is a silent staleness, and the analyst
  // has no way to see it. Re-analysis is opt-in rather than automatic because it rewrites stored
  // findings — it should be a decision, not a side effect of upgrading.
  reanalyzeStale?: boolean;
  // Apply the behaviour rules to the DECODED text (#909 item 2). Omitted, the decode still happens
  // and the payload is still shown — it simply is not re-graded.
  gradeDerived?: DerivedTextGrader;
}

// Apply deobfuscation to every unprocessed event in the case's forensic timeline.
// Idempotent: events with an existing `deobfuscated` block are skipped.
export function applyDeobfuscation(
  state: InvestigationState,
  options: DeobfuscationApplyOptions = {},
): DeobfuscationApplyResult {
  const iocs: IOC[] = state.iocs.map((i) => ({ ...i }));
  let nextSeq = nextIocSeq(iocs);
  let deobfuscatedCount = 0;
  let reanalyzed = 0;
  let newIocs = 0;
  const now = new Date().toISOString();

  // Ids a PRIOR deobfuscation result pointed at, and the ids that existed before any decoding —
  // together they say which indicators this run is allowed to retire. See the prune below.
  const priorIocIds = new Set<string>();
  for (const e of state.forensicTimeline) for (const id of e.deobfuscated?.iocs ?? []) priorIocIds.add(id);
  const preexistingIocIds = new Set(state.iocs.map((i) => i.id).filter((id) => !priorIocIds.has(id)));

  const forensicTimeline: ForensicEvent[] = state.forensicTimeline.map((event) => {
    const prior = event.deobfuscated;
    const stale = (prior?.version ?? 0) < DECODER_VERSION;
    if (prior && !(options.reanalyzeStale && stale)) return { ...event }; // already processed

    // The layered decoder first; the single-layer one remains the fallback so a payload shape it
    // still handles alone keeps working.
    const layered = decodeLayers(event.description);
    const result = layered
      ? {
          decoded: layered.decoded,
          method: layered.steps[0]?.method ?? "base64",
          rawIocs: extractIocsFromText(layered.decoded),
          steps: layered.steps,
          partial: layered.partial,
          version: layered.version,
        }
      : deobfuscateText(event.description);
    if (!result) return { ...event };

    if (prior) reanalyzed++;
    deobfuscatedCount++;

    // Add extracted IOCs to the case's IOC list, deduping by value.
    const extractedIds: string[] = [];
    for (const raw of result.rawIocs) {
      const existing = iocs.find((i) => i.value.toLowerCase() === raw.value.toLowerCase());
      if (existing) {
        extractedIds.push(existing.id);
      } else {
        const id = padIocId(nextSeq++);
        iocs.push({ id, type: raw.type, value: raw.value, firstSeen: event.timestamp || now });
        extractedIds.push(id);
        newIocs++;
      }
    }

    // Apply the repository's behaviour classifier to the DERIVED text (#909 item 2). Decoding a
    // payload and then grading only the wrapper is how an Invoke-Mimikatz that arrived base64-encoded
    // stays at the severity of "a powershell.exe ran". The grade can only go UP: a decoded payload is
    // additional evidence about the same event, never grounds to soften what was already known.
    const derived = options.gradeDerived?.(result.decoded) ?? null;
    const lifted: Partial<ForensicEvent> = {};
    if (derived) {
      const want: ForensicEvent["severity"] =
        derived.weight === "strong" ? "High" : derived.weight === "weak" ? "Medium" : event.severity;
      if (SEVERITY_RANK[want] > SEVERITY_RANK[event.severity]) lifted.severity = want;
      if (derived.mitre.length > 0) {
        lifted.mitreTechniques = [...new Set([...(event.mitreTechniques ?? []), ...derived.mitre])];
      }
    }

    return {
      ...event,
      ...lifted,
      deobfuscated: {
        decoded: result.decoded,
        method: result.method,
        iocs: extractedIds,
        ...("steps" in result ? { steps: result.steps } : {}),
        ...("partial" in result ? { partial: result.partial } : {}),
        ...("version" in result ? { version: result.version } : { version: 1 }),
      },
    };
  });

  if (deobfuscatedCount === 0 && newIocs === 0) {
    return { state, deobfuscated: 0, newIocs: 0, reanalyzed: 0 };
  }

  // A re-decode replaces the event's IOC list. Without this, an indicator recovered by the OLD
  // decoder — possibly from a payload the new one reads differently — stays in the case, visible
  // and scored, referenced by nothing. Only ids this run orphaned are dropped: an indicator that
  // predates the deobfuscation pass, or that any surviving event still points at, is left alone.
  const referenced = new Set<string>();
  for (const e of forensicTimeline) for (const id of e.deobfuscated?.iocs ?? []) referenced.add(id);
  const orphaned = new Set(
    [...priorIocIds].filter((id) => !referenced.has(id) && !preexistingIocIds.has(id)),
  );
  const keptIocs = orphaned.size > 0 ? iocs.filter((i) => !orphaned.has(i.id)) : iocs;

  return {
    state: { ...state, forensicTimeline, iocs: keptIocs, updatedAt: now },
    deobfuscated: deobfuscatedCount,
    newIocs,
    reanalyzed,
  };
}
