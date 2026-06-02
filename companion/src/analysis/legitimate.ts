import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "./stateTypes.js";

// A kind of thing the client has confirmed is legitimate (benign activity they
// performed). The AI must exclude these from analysis entirely.
//   - "finding" : matched by the finding title/keyword
//   - "ioc"     : matched by the exact IOC value
//   - "event"   : matched by the forensic event id — the raw event is PRESERVED in
//                 state (it's evidence) but hidden from the timeline view and
//                 excluded from synthesis input, so un-marking fully restores it.
export type LegitimateKind = "finding" | "ioc" | "event";

export interface LegitimateMarker {
  id: string;                  // natural key: `${kind}:${ref}`
  kind: LegitimateKind;
  ref: string;                 // IOC value | finding title/keyword | forensic event id
  note: string;                // why it's legitimate (e.g. "client's red-team ran this")
  markedAt: string;
  label?: string;              // optional human-readable label (e.g. an event's description) for display
}

export function markerId(kind: LegitimateKind, ref: string): string {
  return `${kind}:${ref.trim().toLowerCase()}`;
}

// The set of forensic event ids the client confirmed legitimate (lowercased).
export function legitimateEventIds(markers: LegitimateMarker[]): Set<string> {
  return new Set(
    markers.filter((m) => m.kind === "event").map((m) => m.ref.trim().toLowerCase()),
  );
}

// Drop forensic events the client confirmed legitimate, matched by event id. Pure
// and reversible: callers filter a COPY for the view/synthesis input; the raw
// timeline in persisted state is never mutated, so un-marking restores the event.
export function filterLegitimateEvents<T extends { id: string }>(
  events: readonly T[],
  markers: LegitimateMarker[],
): T[] {
  const ids = legitimateEventIds(markers);
  if (ids.size === 0) return [...events];
  return events.filter((e) => !ids.has(e.id.trim().toLowerCase()));
}

// Drop findings/IOCs the client confirmed legitimate. IOCs match by exact value;
// findings match when the marker ref appears in (or equals) the finding title.
// Forensic events are handled separately (filterLegitimateEvents) so the raw
// evidence is preserved rather than stripped from saved state.
export function applyLegitimate(state: InvestigationState, markers: LegitimateMarker[]): InvestigationState {
  if (markers.length === 0) return state;
  const iocRefs = new Set(markers.filter((m) => m.kind === "ioc").map((m) => m.ref.trim().toLowerCase()));
  const findingRefs = markers.filter((m) => m.kind === "finding").map((m) => m.ref.trim().toLowerCase()).filter(Boolean);

  const iocs = state.iocs.filter((i) => !iocRefs.has(i.value.trim().toLowerCase()));
  const findings = state.findings.filter((f) => {
    const title = f.title.trim().toLowerCase();
    return !findingRefs.some((ref) => title === ref || title.includes(ref) || ref.includes(title));
  });
  return { ...state, iocs, findings };
}

// A prompt block telling the model what to treat as benign. Only finding/IOC
// markers are listed — legitimate EVENTS are already removed from the timeline
// the model is given, so naming their (opaque) ids here would add no signal.
export function buildLegitimateContext(markers: LegitimateMarker[]): string {
  const relevant = markers.filter((m) => m.kind === "finding" || m.kind === "ioc");
  if (relevant.length === 0) return "";
  const lines = relevant.map((m) => `- ${m.kind}: ${m.ref}${m.note ? ` — ${m.note}` : ""}`).join("\n");
  return (
    "CONFIRMED LEGITIMATE BY THE CLIENT (benign activity the client performed). Do NOT report these " +
    "as findings or IOCs, and EXCLUDE them from the attacker path, key questions, and severity:\n" +
    lines
  );
}

export class LegitimateStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "legitimate.json");
  }

  async load(caseId: string): Promise<LegitimateMarker[]> {
    try {
      return JSON.parse(await readFile(this.path(caseId), "utf8")) as LegitimateMarker[];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async save(caseId: string, markers: LegitimateMarker[]): Promise<void> {
    const target = this.path(caseId);
    const tmp = target + ".tmp";
    await writeFile(tmp, JSON.stringify(markers, null, 2), "utf8");
    await rename(tmp, target);
  }
}
