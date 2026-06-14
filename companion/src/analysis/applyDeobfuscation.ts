// Scan a case's forensic timeline for obfuscated command lines, decode them, extract IOCs
// from the decoded payload, and attach the result to each event as `event.deobfuscated`.
// Pure: returns a new state, never mutates.
//
// Events already carrying `deobfuscated` are not re-processed (idempotent).
// The extracted IOCs are added to state.iocs (deduped by value) and their canonical
// ids are stored in the event's deobfuscated.iocs array.

import type { InvestigationState, ForensicEvent, IOC } from "./stateTypes.js";
import { deobfuscateText } from "./deobfuscate.js";

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
  deobfuscated: number;  // events decoded this run
  newIocs: number;       // net-new IOCs added from decoded content
}

// Apply deobfuscation to every unprocessed event in the case's forensic timeline.
// Idempotent: events with an existing `deobfuscated` block are skipped.
export function applyDeobfuscation(state: InvestigationState): DeobfuscationApplyResult {
  const iocs: IOC[] = state.iocs.map((i) => ({ ...i }));
  let nextSeq = nextIocSeq(iocs);
  let deobfuscatedCount = 0;
  let newIocs = 0;
  const now = new Date().toISOString();

  const forensicTimeline: ForensicEvent[] = state.forensicTimeline.map((event) => {
    if (event.deobfuscated) return { ...event }; // already processed

    const result = deobfuscateText(event.description);
    if (!result) return { ...event };

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

    return {
      ...event,
      deobfuscated: {
        decoded: result.decoded,
        method: result.method,
        iocs: extractedIds,
      },
    };
  });

  if (deobfuscatedCount === 0 && newIocs === 0) {
    return { state, deobfuscated: 0, newIocs: 0 };
  }

  return {
    state: { ...state, forensicTimeline, iocs, updatedAt: now },
    deobfuscated: deobfuscatedCount,
    newIocs,
  };
}
