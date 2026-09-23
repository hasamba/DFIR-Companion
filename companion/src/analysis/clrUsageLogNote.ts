// The CLR usage-log fact, owned in one place (#1559).
//
// The CLR writes `%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageLogs\<host>.exe.log` the first time a
// process loads .NET. rundll32, regsvr32, mshta and the rest never load .NET on their own, so a log
// named after one of them is the disk trace of Cobalt Strike execute-assembly (the beacon's
// sacrificial process hosting Seatbelt, SharpShares, Rubeus…). The bundled tags.yaml rule
// `clr_usagelog_lolbin_host` grades the row; this module says what the row MEANS, as a registered
// derived note on the description — a tagger rule's description never reaches the AI, and in
// scenario 019 the only trace of the attacker's .NET tooling was folded into a file-write finding
// with nothing saying what the file was.
//
// The note is appended by applyToForensicEvent only when that rule matched, so an analyst who
// disables the rule disables the note with it. The path regex below mirrors the rule's; the test
// runs both over the same inputs.

import type { ForensicEvent } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";

export const CLR_USAGE_LOG_RULE_ID = "clr_usagelog_lolbin_host";
export const CLR_USAGE_LOG_MARKER = "[CLR usage log:";

const USAGE_LOG_RE =
  /\\microsoft\\clr_v[24]\.0(?:_32)?\\usagelogs\\((?:rundll32|regsvr32|mshta|wmic|msxsl|dllhost|werfault|svchost|notepad)\.exe)\.log$/iu;

/** The host process the log is named after (`rundll32.exe`, as written on disk), or null. */
export function clrUsageLogHost(path: string | undefined): string | null {
  return USAGE_LOG_RE.exec(path ?? "")?.[1] ?? null;
}

/**
 * The event with the note appended when the CLR usage-log rule matched it. Returns the input
 * unchanged when the rule did not match, the path names no covered host, or the note is already
 * there — so a second tagger run is a no-op.
 */
export function withClrUsageLogNote(event: ForensicEvent, ruleIds: readonly string[]): ForensicEvent {
  if (!ruleIds.includes(CLR_USAGE_LOG_RULE_ID)) return event;
  const host = clrUsageLogHost(event.path);
  if (!host || (event.description ?? "").includes(CLR_USAGE_LOG_MARKER)) return event;
  const note = `.NET assembly ran inside ${host} — typical of Cobalt Strike execute-assembly`;
  return { ...event, description: appendDerivedNote(event.description, CLR_USAGE_LOG_MARKER, note) };
}
