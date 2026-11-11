// Which IOCs were extracted from a High or Critical event (#2543). A cloud identity IOC (an IAM
// principal, an access key, a created policy name) is typed `other` and never gets a threat-intel
// verdict, so the composite risk score calls it an observation. The user's rule: one extracted from a
// High/Critical event counts as signal and is listed in the report IOC table.
//
// The link is the IOC's own `extractedFrom` (the importer's authoritative event id), never a text
// match against descriptions and never "any linked event": every binary hash is an IOC and process
// rows carry MITRE tags, so a looser rule would list them all (CLAUDE.md §7). Pure.

import type { ForensicEvent, IOC } from "./stateTypes.js";
import { SEVERITY_RANK } from "./forensicGate.js";

/** Ids of the IOCs whose `extractedFrom` names a High or Critical event in `events`. */
export function iocsLinkedToHighEvent(
  iocs: readonly Pick<IOC, "id" | "extractedFrom">[],
  events: readonly Pick<ForensicEvent, "id" | "severity">[],
): Set<string> {
  const highIds = new Set(
    events.filter((e) => SEVERITY_RANK[e.severity] >= SEVERITY_RANK.High).map((e) => e.id),
  );
  const out = new Set<string>();
  if (!highIds.size) return out;
  for (const ioc of iocs) {
    if ((ioc.extractedFrom ?? []).some((id) => highIds.has(id))) out.add(ioc.id);
  }
  return out;
}
