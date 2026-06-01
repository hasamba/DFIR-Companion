import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "./stateTypes.js";

// A finding or IOC the client has confirmed is legitimate (benign activity they
// performed). The AI must exclude these from findings/IOCs/attacker-path entirely.
export interface LegitimateMarker {
  id: string;                  // natural key: `${kind}:${ref}`
  kind: "finding" | "ioc";
  ref: string;                 // the IOC value, or the finding title/keyword to exclude
  note: string;                // why it's legitimate (e.g. "client's red-team ran this")
  markedAt: string;
}

export function markerId(kind: "finding" | "ioc", ref: string): string {
  return `${kind}:${ref.trim().toLowerCase()}`;
}

// Drop findings/IOCs the client confirmed legitimate. IOCs match by exact value;
// findings match when the marker ref appears in (or equals) the finding title.
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

// A prompt block telling the model what to treat as benign.
export function buildLegitimateContext(markers: LegitimateMarker[]): string {
  if (markers.length === 0) return "";
  const lines = markers.map((m) => `- ${m.kind}: ${m.ref}${m.note ? ` — ${m.note}` : ""}`).join("\n");
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
