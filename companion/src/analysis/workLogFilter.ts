import type { ForensicEvent } from "./stateTypes.js";

// Phrases that describe the investigator OPERATING the DFIR tooling (Velociraptor
// hunts, notebooks, VQL, "Response and Monitoring", EventLog searches) rather than
// real incident activity on the system under investigation. These belong in the
// work log, not the forensic timeline. Patterns key on tool nouns + actions
// together (not bare words) to avoid dropping genuine host events such as
// "velociraptor.exe process created" or "Outbound RDP connection initiated".
const TOOL_PATTERNS: RegExp[] = [
  /\bvelociraptor\b.*\b(response|eventlog|notebook|monitoring|vql|logged|executing|executed|performed|search|accessed)\b/i,
  /\bnotebookmanager\b/i,
  /\bnotebook\b.*\b(accessed|cell|canceled|cancelled|created)\b/i,
  /\bhunt\b.*\b(created|started|stopped|paused|expired|scheduled|launched)\b/i,
  /\bresponse and monitoring\b/i,
  /\beventlog\b.*\b(search|analysis|query)\b/i,
  /\bvql command\b/i,
];

// True when an event describes analyst/tool usage rather than a real incident event.
export function isAnalystWorkLog(description: string): boolean {
  return TOOL_PATTERNS.some((re) => re.test(description));
}

export function partitionWorkLog(events: ForensicEvent[]): { keep: ForensicEvent[]; removed: ForensicEvent[] } {
  const keep: ForensicEvent[] = [];
  const removed: ForensicEvent[] = [];
  for (const e of events) (isAnalystWorkLog(e.description) ? removed : keep).push(e);
  return { keep, removed };
}
