import { randomUUID } from "node:crypto";
import { emptyState, type InvestigationState } from "./stateTypes.js";
import { EMPTY_OUTLINE, type ForensicOutline } from "./forensicRows.js";
import type { StateStore } from "./stateStore.js";

/**
 * What an import compares itself against (#1874), in place of a full copy of the case held from the
 * moment the import took the case until it settled.
 *
 * - `overview` is every field but the forensic timeline — the IOCs the IOC diff reads, the rename
 *   ledger, the small fields the undo checkpoint restores.
 * - `outline` is the forensic timeline as ids, row ids and the three fields the timeline diff reads.
 * - `journalToken` names the armed import journal (analysis/caseSqliteWorkerRows.ts): the stored
 *   image of every forensic row changed or removed after the snapshot, which is what the undo
 *   checkpoint restores and what "old rows this import touched" means. The snapshot and the arming
 *   are one transaction, so no write can fall between them.
 *
 * A caller that still takes a full snapshot (the Velociraptor hunt and external-ingest paths) hands
 * that state in; `baselineFromState` wraps it with `full` set and no journal, and every step that
 * needs to know which old rows changed then reads the whole timeline instead.
 */
export interface ImportBaseline {
  readonly kind: "import-baseline";
  caseId: string;
  overview: InvestigationState;
  outline: ForensicOutline;
  journalToken: string | null;
  /** The case had no state at capture: no old row exists, so none can have been touched. */
  empty: boolean;
  /** The full pre-import state, only when a legacy caller supplied one. */
  full?: InvestigationState;
}

export function isImportBaseline(v: unknown): v is ImportBaseline {
  return !!v && typeof v === "object" && (v as { kind?: unknown }).kind === "import-baseline";
}

/** Snapshot the case and arm its import journal. Release it with releaseImportBaseline. */
export async function captureImportBaseline(stateStore: StateStore, caseId: string): Promise<ImportBaseline> {
  const token = randomUUID();
  const captured = await stateStore.captureImportBaseline(caseId, token);
  if (!captured) {
    return {
      kind: "import-baseline",
      caseId,
      overview: emptyState(caseId),
      outline: { ...EMPTY_OUTLINE },
      journalToken: null,
      empty: true,
    };
  }
  return {
    kind: "import-baseline",
    caseId,
    overview: captured.overview,
    outline: captured.outline,
    journalToken: token,
    empty: false,
  };
}

/** Disarm the journal this baseline armed. A newer section's journal is left alone. Never throws. */
export async function releaseImportBaseline(
  stateStore: StateStore,
  baseline: ImportBaseline | null,
): Promise<void> {
  if (!baseline?.journalToken) return;
  try {
    await stateStore.disarmImportJournal(baseline.caseId, baseline.journalToken);
  } catch {
    // The next section clears and re-arms it; an armed journal only costs a copy of each row changed.
  }
}

/** A legacy caller's full snapshot as a baseline: no journal, so touched rows are unknown. */
export function baselineFromState(state: InvestigationState): ImportBaseline {
  const rows = state.forensicTimeline ?? [];
  return {
    kind: "import-baseline",
    caseId: state.caseId,
    overview: { ...state, forensicTimeline: [] },
    outline: {
      rowIds: rows.map(() => -1),
      ids: rows.map((e) => e.id),
      timestamps: rows.map((e) => e.timestamp),
      descriptions: rows.map((e) => e.description),
      severities: rows.map((e) => e.severity),
    },
    journalToken: null,
    empty: false,
    full: state,
  };
}

export function toImportBaseline(before: InvestigationState | ImportBaseline): ImportBaseline {
  return isImportBaseline(before) ? before : baselineFromState(before);
}

/** Every id the case held before the import — forensic rows then IOCs (importRunRecorder). */
export function baselineEntityIds(baseline: ImportBaseline): string[] {
  return [
    ...baseline.outline.ids.filter((id): id is string => typeof id === "string"),
    ...baseline.overview.iocs.map((ioc) => ioc.id),
  ];
}
