// Showing a service principal's name after its id on Azure activity rows (#2490).
//
// The Azure Activity Log names a service-principal caller by a GUID; the name lives in other
// uploads (Entra sign-ins, often Info, and directory audits). The importers record id → name pairs
// in the case's ledger (principalNames.ts); this pass rewrites the forensic rows from it, at the one
// seam every import crosses (routes/importSettle.ts), after Undo/Redo, after a synthesis save that
// kept older rows, and at promotion.
//
// It is a RECOMPUTATION, modelled on the host-rename carry (#1495): every eligible row has the
// suffix this pass wrote (`callerName`) removed, then the ledger's single name inserted again — so a
// conflicting second name or an Undo that forgets the name takes the suffix away, and nothing here is
// a one-way door.
//
// What it never touches:
//   - record text: a suffix is removed only when it is exactly the one `callerName` says the carry
//     wrote; a row whose caller field itself reads "<guid> (x)" keeps it, and is never given a second;
//   - any row but an Azure activity row whose description starts "Azure <operation> by <GUID>" with
//     the GUID ending the caller token — summaries ("Azure compute lifecycle: …") and other providers
//     are left alone;
//   - the canonical envelope (actor.name stays the raw caller: correlation and the collector-footprint
//     tag read it), `aggKey` (grouping keys on the id), severity and MITRE;
//   - the super-timeline: its copies keep the raw id, and it is never read to learn a name.
//
// Pure: same object back when nothing changed.

import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { principalNameLookup, type PrincipalLedger } from "./principalNames.js";
import { FORMAT_CHARS } from "./bidiControl.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";

/** What a row shows after the id. Adversary-controlled text: bounded and neutralised. */
export const PRINCIPAL_NAME_SHOWN_MAX = 64;

/**
 * The text a row shows: brackets and parentheses gone (a name can never close the suffix early or
 * fake a qualifier), 32+ hex runs broken (correlation reads them as file hashes), bounded.
 */
export function displayPrincipalName(name: string): string {
  const shown = breakHashRuns(showToken(name.replace(FORMAT_CHARS, "")))
    .replace(/[()]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return shown.length > PRINCIPAL_NAME_SHOWN_MAX ? `${shown.slice(0, PRINCIPAL_NAME_SHOWN_MAX - 1)}…` : shown;
}

const AZURE_SOURCE = "Azure Activity";
// The activity row head (cloudActivityImport.ts mapAzure): "Azure <op> by <caller>"; the GUID must
// end the caller token (a space, the role-grant ':' or the end of the text follows it).
const HEAD = /^(Azure \S+ by )([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=[ :]|$)/i;

/** carryPrincipalNames for one row at a time: the row as the ledger says it should read. */
export function principalNameCarrier(ledger: PrincipalLedger): (e: ForensicEvent) => ForensicEvent {
  const lookup = principalNameLookup(ledger.principalNames);
  const any = (ledger.principalNames?.length ?? 0) > 0;
  return (e) => (any || e.callerName ? nameRow(e, lookup) : e);
}

function nameRow(e: ForensicEvent, lookup: (id: string) => string | undefined): ForensicEvent {
  if (!e.sources?.includes(AZURE_SOURCE)) return e;
  const m = HEAD.exec(e.description);
  if (!m) return e;
  const at = m[0].length;
  let rest = e.description.slice(at);
  // A mark whose suffix is no longer there (a re-import restated the text) is stale: drop it and
  // treat the row as unnamed — nothing is removed that the carry cannot prove it wrote.
  const wrote = e.callerName ? ` (${e.callerName})` : "";
  const carried = wrote !== "" && rest.startsWith(wrote);
  if (carried) rest = rest.slice(wrote.length);
  const known = lookup(m[2]);
  const shown = known ? displayPrincipalName(known) : "";
  // A record that already reads " (<name>)" after the id is its own text: never doubled.
  if (shown && !carried && rest.startsWith(` (${shown})`)) return e.callerName ? withoutMark(e) : e;
  const description = `${m[0]}${shown ? ` (${shown})` : ""}${rest}`;
  if (description === e.description && (shown || undefined) === e.callerName) return e;
  const { callerName: _old, ...base } = e;
  return { ...base, description, ...(shown ? { callerName: shown } : {}) };
}

function withoutMark(e: ForensicEvent): ForensicEvent {
  const { callerName: _old, ...base } = e;
  return base;
}

/** Recompute every forensic row's caller name from the case's ledger. */
export function nameCallers(state: InvestigationState): { state: InvestigationState; changed: number } {
  const carry = principalNameCarrier(state);
  let changed = 0;
  const forensicTimeline = state.forensicTimeline.map((e) => {
    const next = carry(e);
    if (next !== e) changed++;
    return next;
  });
  return changed ? { state: { ...state, forensicTimeline }, changed } : { state, changed: 0 };
}
