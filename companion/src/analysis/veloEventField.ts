// A process / command-line field of a Velociraptor detection row, wherever the row keeps it.
//
// A detection row normally carries these at the top level ("NewProcessName", "CommandLine"). An EVTX
// detection post-processed in Velociraptor to cut its size flattens the event into dotted top-level
// keys instead — "EventData.NewProcessName", "EventData.CommandLine" — with no System wrapper and no
// Message. Read top-level only, such a row named no process: its title was the rule alone, its
// details were empty, and every hit of one rule on a host shared one event key and collapsed into a
// single row. A nested EventData object (the unflattened form) is read too.
//
// In its own module because velociraptorImport.ts is frozen at the file-size ledger (#384).

import { getCI, getPath, str } from "./siemImport.js";

type Row = Record<string, unknown>;

/** The first non-empty value among `keys`: top level, then `EventData.<key>` dotted, then nested. */
export function eventField(row: Row, keys: readonly string[]): string {
  for (const k of keys) {
    const v =
      str(getCI(row, k)).trim() ||
      str(getCI(row, `EventData.${k}`)).trim() ||
      str(getPath(row, `EventData.${k}`)).trim();
    if (v) return v;
  }
  return "";
}
