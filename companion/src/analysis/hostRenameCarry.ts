// Re-homing the rows a case already holds once it learns a hostname was a former one (#1495).
//
// A rename is learned by whichever file happens to carry the evidence, and the drop folder imports
// in filename order: on INC-2026-032 the DetectRaptor export (190 rows under the base-image name)
// arrived before the CondensedAccountUsage file that says the base image became DESKTOP-16OJFO6.
// Seeding later parses (importState.ts knownHostIdentity) cannot reach those earlier rows; this
// pass does, at the one seam every import crosses (routes/importSettle.ts).
//
// It is a RECOMPUTATION, not an edit: every eligible row's asset is derived again from the name the
// record wrote (`assetRecord`, kept by the Windows importers on a bare, non-forwarded row) against
// the case's whole ledger — so the same pass that folds a row when a rename is learned unfolds it
// when a later file contradicts the pair (two current names → the map vouches for neither) or
// tightens the bound below the row's date. Nothing here is a one-way door.
//
// What it never touches:
//   - a row without `assetRecord`: a collector-identified row (its asset is the client, whatever
//     the record said), a ForwardedEvents record (names another machine on purpose), and every
//     event from every other importer — `asset` is a generic field, and a Zeek row that happens to
//     name a host called the same thing is not this machine's history;
//   - severity: a sample-corpus demotion made at import stays Info (the row is out of the model's
//     record either way); only its now-contradicted note is removed when the row folds;
//   - the canonical target unless it is the host itself (`kind: "host"` naming the old asset);
//   - a former name that is a live collector identity in the case (HostRenameMap.markCollector).
//
// Pure: returns a new state when anything changed, the same object when nothing did.
//
// The super-timeline holds its own copies of these rows (dual-written, or Info rows that live only
// there) and the state never sees them; `rehomeEvents` is the same recomputation over any row list
// against the state's ledger, returning only the rows that differ, for the settle seam to write back
// through the store (#1508).

import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { HostRenameMap } from "./hostRenameEvidence.js";
import { FORMER_HOST_DESCRIPTION_CAP, shortHostName, withFormerHostSuffix } from "./hostIdentity.js";

const FORMER_HOST_NOTE = /\s*\[logged under former hostname [^\]]*\]/g;
const NOTE_HEAD = "[logged under former hostname ";

// A note the description cap cut short has no closing bracket, and may stop anywhere — even inside
// its fixed words (#2221). Only a description exactly at the cap can end in one.
function stripCutNote(text: string): string {
  if (text.length !== FORMER_HOST_DESCRIPTION_CAP) return text;
  const at = text.lastIndexOf(" [");
  if (at < 0) return text;
  const tail = text.slice(at + 1);
  const cut = NOTE_HEAD.startsWith(tail) || (tail.startsWith(NOTE_HEAD) && !tail.includes("]"));
  return cut ? text.slice(0, at) : text;
}
const SAMPLE_CORPUS_NOTE = /\s*\[detection sample corpus — [^\]]*\]/g;

/**
 * `evenWithoutLedger` re-homes against an EMPTY ledger too (#2221): Undo of the import that taught the
 * case its first rename restores no ledger at all, and its folded rows must go back to the name they
 * wrote. The default skips the scan, because a settle with no ledger has nothing to move.
 */
export interface CarryOptions {
  evenWithoutLedger?: boolean;
}

/** Recompute every eligible row's host from the case's rename ledger. */
export function carryHostRenames(
  state: InvestigationState,
  opts: CarryOptions = {},
): {
  state: InvestigationState;
  changed: number;
} {
  if (!state.hostRenames?.length && !opts.evenWithoutLedger) return { state, changed: 0 };
  const map = HostRenameMap.from(state.hostRenames, state.collectorHostnames);
  let changed = 0;
  const forensicTimeline = state.forensicTimeline.map((e) => {
    const next = rehome(e, map);
    if (next !== e) changed++;
    return next;
  });
  return changed ? { state: { ...state, forensicTimeline }, changed } : { state, changed: 0 };
}

/**
 * The rows among `events` that the case's ledger re-homes, re-homed — nothing else comes back, so
 * the caller writes exactly what changed. Empty when the case has no ledger.
 */
export function rehomeEvents(
  events: readonly ForensicEvent[],
  state: Pick<InvestigationState, "hostRenames" | "collectorHostnames">,
  opts: CarryOptions = {},
): ForensicEvent[] {
  if (!state.hostRenames?.length && !opts.evenWithoutLedger) return [];
  const map = HostRenameMap.from(state.hostRenames, state.collectorHostnames);
  const changed: ForensicEvent[] = [];
  for (const e of events) {
    const next = rehome(e, map);
    if (next !== e) changed.push(next);
  }
  return changed;
}

// The row as the ledger says it should read, or the row itself when nothing differs.
/**
 * carryHostRenames for one row at a time (#1874): the returned function gives the row re-homed, or
 * the same object when the ledger leaves it where it is. Identity when the case has no ledger.
 */
export function hostRenameCarrier(
  state: Pick<InvestigationState, "hostRenames" | "collectorHostnames">,
): (e: ForensicEvent) => ForensicEvent {
  if (!state.hostRenames?.length) return (e) => e;
  const map = HostRenameMap.from(state.hostRenames, state.collectorHostnames);
  return (e) => rehome(e, map);
}

function rehome(e: ForensicEvent, map: HostRenameMap): ForensicEvent {
  if (!e.assetRecord || !e.asset) return e;
  const current = map.currentNameOf(e.assetRecord, e.timestamp);
  const folded = shortHostName(current) !== shortHostName(e.assetRecord);
  const asset = folded ? current : e.assetRecord;
  const base = stripCutNote(e.description)
    .replace(FORMER_HOST_NOTE, "")
    .replace(folded ? SAMPLE_CORPUS_NOTE : /$^/, "");
  const description = folded ? withFormerHostSuffix(base, e.assetRecord) : base;
  if (asset === e.asset && description === e.description) return e;
  const target = e.canonical?.target;
  const retarget = target?.kind === "host" && shortHostName(target.name ?? "") === shortHostName(e.asset);
  return {
    ...e,
    asset,
    description,
    ...(retarget && e.canonical ? { canonical: { ...e.canonical, target: { ...target, name: asset } } } : {}),
  };
}

export type RenameLedger = Pick<InvestigationState, "hostRenames" | "collectorHostnames">;

/**
 * True when what the ledger says about any host differs: a rename learned, unlearned or re-bounded,
 * or a collector identity that now vetoes a fold. Content, not identity — the importer rebuilds the
 * state object on every save.
 */
export function renameLedgerChanged(before: RenameLedger, after: RenameLedger): boolean {
  return (
    JSON.stringify(before.hostRenames ?? []) !== JSON.stringify(after.hostRenames ?? []) ||
    JSON.stringify(before.collectorHostnames ?? []) !== JSON.stringify(after.collectorHostnames ?? [])
  );
}
