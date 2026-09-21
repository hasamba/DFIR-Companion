// The one-line caution a report prints under a finding heading when a deterministic gate lowered
// it (investigation-guidance #6, #1502). Split out of markdown.ts, which sits at its size ledger:
// each new gate in findingGrounding.ts adds a badge here, not there. Order is the order of the
// gates' certainty — no evidence at all, then evidence that cannot support the claim, then evidence
// that does not match it. One badge per finding; the flags are recomputed every synthesis.

import type { Finding } from "../analysis/stateTypes.js";
import { corroborationLabel } from "../analysis/findingGrounding.js";

/** The markdown line under a finding heading, or "" when nothing qualifies it. */
export function findingCautionLine(f: Finding): string {
  if (f.ungrounded)
    return `> ⚠️ **No cited evidence** — treat as a hypothesis, not a fact (confidence capped).`;
  if (f.decoyBinary)
    return `> ⚠️ **Renamed shell, not the named tool** — every cited event is a binary that identifies as a plain shell (or a file trace of it); the command line is a label, not a run. Severity floored and confidence capped.`;
  if (f.contentMismatch)
    return `> ⚠️ **Citation mismatch** — a claimed detail (e.g. an IP) never appears in the cited events; severity floored and confidence capped pending verification.`;
  if (f.lateralUnconfirmed)
    return `> ⚠️ **Unconfirmed lateral movement** — the destination host has no confirmed malicious activity of its own; the cited logon may be a legitimate session by a reused account. Severity floored and confidence capped until the source is tied to a compromised node.`;
  if (f.corroboration) return `- Corroboration: ${corroborationLabel(f)}`;
  return "";
}
