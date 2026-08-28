// Grading a Windows event that arrives FLAT.
//
// A custom VQL artifact SELECTs the columns it wants, so its rows carry a bare `EventID` with none
// of the wrapper mapWindows() keys on — no Channel, no EventData, no System block. velociraptorImport
// sends such a row to the generic key=value dump, which grades Info, and Info never reaches the
// forensic timeline. On one benchmark collection that hid every explicit-credential logon (4648) the
// collection held. The dump describes the row perfectly well; the one thing it cannot supply is what
// the event TYPE means, so that is all this adds.
//
// Kept out of siemImport.ts, which is frozen at its current size by the file-size ledger (#384) —
// see check-file-size.mjs.
import { getCI, firstStr, worst, WIN_EVENTS, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

// The two logs WIN_EVENTS actually describes. A row naming any other one — Application, a vendor
// Operational channel — is numbered by that log, which this table knows nothing about.
const WIN_EID_LOG = /^(security|system)(\.evtx)?$/i;
const LOG_NAME_KEYS = ["Channel", "LogName", "Log", "EventLog", "LogFile"];

// IDs that name their own log, for a row that states none. No other provider issues a Security audit
// ID, so 1102 and the 4624-5145 block are safe to grade from the number alone. The table's System
// entries (104, 6005, 6006, 7034-7045) are NOT: any Application or Operational provider numbering its
// own events collides with them, and a bare 104 would turn such a row into a High log-clear finding.
const SELF_SCOPED_EID = (eid: number): boolean => eid === 1102 || (eid >= 4624 && eid <= 5145);

/**
 * Raise an event's grade to what its Event ID means, when the row proves which log the ID came from.
 *
 * WIN_EVENTS is keyed by ID ALONE — the same hazard POWERSHELL_EVENTS is split out to avoid — so the
 * row must first be shown to belong to a log that table describes. Two gates do it: the log name when
 * the row states one, and the ID's own range when it does not. Raises only, via worst(), so a grade
 * the row already earned elsewhere always wins.
 */
export function overlayFlatWindowsEid(row: Row, m: MappedEvent): void {
  const eid = Number(getCI(row, "EventID") ?? getCI(row, "EventId"));
  const def = Number.isFinite(eid) ? WIN_EVENTS[eid] : undefined;
  if (!def) return;
  const log = firstStr(row, LOG_NAME_KEYS).trim();
  if (log ? !WIN_EID_LOG.test(log) : !SELF_SCOPED_EID(eid)) return;
  m.severity = worst(m.severity, def.severity);
  for (const t of def.mitre ?? []) if (!m.mitre.includes(t)) m.mitre.push(t);
}
