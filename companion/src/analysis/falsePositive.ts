import { readFile } from "node:fs/promises";
import { atomicWrite } from "../storage/atomicWrite.js";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "./stateTypes.js";

// A kind of thing the client has confirmed is NOT a real threat — either because it's
// authorized/benign activity the client performed, or because a tool/rule mis-flagged it.
// The AI must exclude these from analysis entirely.
//   - "finding" : matched by the finding title/keyword
//   - "ioc"     : matched by the exact IOC value
//   - "event"   : matched by the forensic event id — the raw event is PRESERVED in
//                 state (it's evidence) but hidden from the timeline view and
//                 excluded from synthesis input, so un-marking fully restores it.
export type FalsePositiveKind = "finding" | "ioc" | "event";

// A structured reason, so false positives can be aggregated/reported on (issue #227), not just
// read as free text. "other" requires the `note` free-text field to be non-empty.
export const FALSE_POSITIVE_REASONS = [
  "known-good-tool",
  "authorized-test",
  "detection-misfire",
  "duplicate",
  "other",
] as const;
export type FalsePositiveReason = (typeof FALSE_POSITIVE_REASONS)[number];

export interface FalsePositiveMarker {
  id: string;                    // natural key: `${kind}:${ref}`
  kind: FalsePositiveKind;
  ref: string;                   // IOC value | finding title/keyword | forensic event id
  reason: FalsePositiveReason;
  note: string;                  // free-text elaboration (required by callers when reason === "other")
  markedAt: string;
  markedBy: string;              // analyst name/id; "anonymous" when not supplied
  label?: string;                // optional human-readable label (e.g. an event's description) for display
}

export function markerId(kind: FalsePositiveKind, ref: string): string {
  return `${kind}:${ref.trim().toLowerCase()}`;
}

// The set of forensic event ids the client confirmed false-positive (lowercased).
export function falsePositiveEventIds(markers: FalsePositiveMarker[]): Set<string> {
  return new Set(
    markers.filter((m) => m.kind === "event").map((m) => m.ref.trim().toLowerCase()),
  );
}

// Drop forensic events the client confirmed false-positive, matched by event id. Pure and
// reversible: callers filter a COPY for the view/synthesis input; the raw timeline in persisted
// state is never mutated, so un-marking restores the event.
export function filterFalsePositiveEvents<T extends { id: string }>(
  events: readonly T[],
  markers: FalsePositiveMarker[],
): T[] {
  const ids = falsePositiveEventIds(markers);
  if (ids.size === 0) return [...events];
  return events.filter((e) => !ids.has(e.id.trim().toLowerCase()));
}

// Drop findings/IOCs the client confirmed false-positive. IOCs match by exact value; findings
// match when the marker ref appears in (or equals) the finding title. Forensic events are handled
// separately (filterFalsePositiveEvents) so the raw evidence is preserved rather than stripped
// from saved state.
export function applyFalsePositive(state: InvestigationState, markers: FalsePositiveMarker[]): InvestigationState {
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

// A prompt block telling the model what to treat as benign/non-threat. Only finding/IOC markers
// are listed — false-positive EVENTS are already removed from the timeline the model is given, so
// naming their (opaque) ids here would add no signal.
export function buildFalsePositiveContext(markers: FalsePositiveMarker[]): string {
  const relevant = markers.filter((m) => m.kind === "finding" || m.kind === "ioc");
  if (relevant.length === 0) return "";
  const lines = relevant
    .map((m) => `- ${m.kind}: ${m.ref} [${m.reason}]${m.note ? ` — ${m.note}` : ""}`)
    .join("\n");
  return (
    "CONFIRMED NOT A REAL THREAT BY THE CLIENT (authorized activity or a detection error). Do NOT " +
    "report these as findings or IOCs, and EXCLUDE them from the attacker path, key questions, and severity:\n" +
    lines
  );
}

export class FalsePositiveStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "false-positive.json");
  }

  private legacyPath(caseId: string): string {
    return join(this.cases.stateDir(caseId), "legitimate.json");
  }

  async load(caseId: string): Promise<FalsePositiveMarker[]> {
    try {
      return JSON.parse(await readFile(this.path(caseId), "utf8")) as FalsePositiveMarker[];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    // One-time migration: an older case may only have the pre-rename legitimate.json. Read it,
    // map each marker onto the new shape (reason defaults to "other", its old note preserved),
    // persist under the new filename, and leave the legacy file in place as a safety net.
    try {
      const legacyRaw = JSON.parse(await readFile(this.legacyPath(caseId), "utf8")) as Array<{
        id: string; kind: FalsePositiveKind; ref: string; note: string; markedAt: string; label?: string;
      }>;
      const migrated: FalsePositiveMarker[] = legacyRaw.map((m) => ({
        id: m.id,
        kind: m.kind,
        ref: m.ref,
        reason: "other",
        note: m.note ?? "",
        markedAt: m.markedAt,
        markedBy: "anonymous",
        ...(m.label ? { label: m.label } : {}),
      }));
      await this.save(caseId, migrated);
      return migrated;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }

  async save(caseId: string, markers: FalsePositiveMarker[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(markers, null, 2));
  }
}
