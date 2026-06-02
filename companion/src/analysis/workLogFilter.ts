import type { ForensicEvent } from "./stateTypes.js";

// Phrases that describe the investigator OPERATING the DFIR tooling (Velociraptor
// hunts, notebooks, VQL, "Response and Monitoring", EventLog searches) or narrating
// the investigation PROCESS ("data collection", "analysis completed") rather than
// real incident activity on the system under investigation. These belong in the
// work log, not the forensic timeline.
//
// Two families:
//  1. TOOL_PATTERNS — tool noun + a usage verb (order-sensitive legacy patterns).
//  2. PROCESS_NARRATION — investigation-process narration in EITHER word order, e.g.
//     "Performed initial data collection with Velociraptor", "Further data analyzed in
//     Velociraptor", "Surveying the DFIR Companion Dashboard". A weak model emits these
//     (often stamped with the screenshot CAPTURE time) when a screenshot shows only the
//     tool UI / our own dashboard and no real artifact rows.
//
// Patterns key on tool nouns + actions together (not bare words) to avoid dropping
// genuine host events such as "velociraptor.exe process created" or "Outbound RDP
// connection initiated".
const TOOL_PATTERNS: RegExp[] = [
  /\bvelociraptor\b.*\b(response|eventlog|notebook|monitoring|vql|logged|executing|executed|performed|search|accessed)\b/i,
  /\bnotebookmanager\b/i,
  /\bnotebook\b.*\b(accessed|cell|canceled|cancelled|created)\b/i,
  /\bhunt\b.*\b(created|started|stopped|paused|expired|scheduled|launched)\b/i,
  /\bresponse and monitoring\b/i,
  /\beventlog\b.*\b(search|analysis|query)\b/i,
  /\bvql command\b/i,
];

// Our own application / dashboard is never the system under investigation.
const OWN_TOOL = /\b(dfir companion|companion dashboard)\b/i;

// Analyst-process verbs paired with a tool/UI noun, matched in EITHER order.
const PROCESS_NARRATION: RegExp[] = [
  OWN_TOOL,
  /\bdata collection\b/i,                                  // "performed/continued/initial data collection"
  /\bcollecting data\b/i,
  /\bdata (?:was |were )?analy[sz]\w*\b/i,                 // "data analyzed", "data was analysed"
  /\bdata analysis\b/i,
  /\binvestigation context\b/i,
  // "<process verb> … <tool>"  e.g. "Further data analyzed in Velociraptor"
  /\b(survey\w*|review\w*|investigat\w*|analy[sz]\w*|collect\w*)\b[^.]*\b(velociraptor|dashboard|companion|notebook)\b/i,
  // "<tool> … <process verb>"  e.g. "Velociraptor data collection continued"
  /\b(velociraptor|dashboard|companion|notebook)\b[^.]*\b(survey\w*|review\w*|data collection|analy[sz]\w*|collect\w*)\b/i,
  // "<stage word> … analysis …"  e.g. "Ongoing analysis completed", "Final analysis stages reached"
  /\b(initial|ongoing|further|continued|final|completed|preliminary)\b[^.]*\banaly[sz]\w*\b/i,
  /\banaly[sz]\w*\b[^.]*\b(completed|continued|ongoing|performed|reached|stage)\w*\b/i,
];

// True when an event describes analyst/tool usage or investigation-process narration
// rather than a real incident event on the system(s) under investigation.
export function isAnalystWorkLog(description: string): boolean {
  return TOOL_PATTERNS.some((re) => re.test(description))
    || PROCESS_NARRATION.some((re) => re.test(description));
}

export function partitionWorkLog(events: ForensicEvent[]): { keep: ForensicEvent[]; removed: ForensicEvent[] } {
  const keep: ForensicEvent[] = [];
  const removed: ForensicEvent[] = [];
  for (const e of events) (isAnalystWorkLog(e.description) ? removed : keep).push(e);
  return { keep, removed };
}
