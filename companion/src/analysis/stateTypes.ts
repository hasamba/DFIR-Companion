export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type FindingStatus = "open" | "confirmed" | "dismissed";
export type ThreadStatus = "open" | "closed";

// One threat-intel lookup result for an IOC (VirusTotal, MalwareBazaar, AbuseIPDB…).
export interface IocEnrichment {
  source: string;                                              // display label, e.g. "VirusTotal" | "MalwareBazaar" | "ThreatFox"
  provider?: string;                                           // owning provider name (e.g. "Hunting.ch") when it differs from `source` — a fan-out provider emits several sources; dedup/re-check key on this, falling back to `source`
  verdict: "malicious" | "suspicious" | "harmless" | "unknown";
  score?: string;                                              // human summary, e.g. "52/73 detections", "100% abuse"
  detections?: number;                                         // malicious engine count (where applicable)
  total?: number;
  tags?: string[];                                             // malware family / classification labels
  link?: string;                                               // permalink to the report
  fetchedAt: string;                                           // ISO time the lookup was made
  // Geo coordinates (#133): set by the GeoIP provider so the map can plot the IOC. Optional —
  // older enrichments without them still validate; nothing else needs wiring.
  lat?: number;
  lon?: number;
  country?: string;
  city?: string;
}

export interface IOC {
  id: string;
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "other";
  value: string;
  firstSeen: string;
  enrichments?: IocEnrichment[];                               // threat-intel HITS (added by the enrich pass)
  enrichedBy?: string[];                                       // provider names that have CHECKED this IOC (hit or not) — so a newly-enabled provider re-checks every IOC, and checked ones aren't re-queried
}

export interface Finding {
  id: string;
  severity: Severity;
  confidence?: number;          // 0–100: AI certainty this finding is real (absent = unknown)
  confidenceReason?: string;    // one-sentence why (evidence strength, source corroboration, model certainty)
  title: string;
  description: string;
  relatedIocs: string[];        // IOC ids
  sourceScreenshots: string[];  // screenshot filenames
  mitreTechniques: string[];    // technique ids, e.g. "T1059"
  firstSeen: string;
  lastUpdated: string;
  status: FindingStatus;
}

export interface Thread {
  id: string;
  description: string;
  status: ThreadStatus;
  openedAt: string;
  closedAt: string | null;
}

export interface TimelineEntry {
  timestamp: string;
  windowSequence: number;
  description: string;
  sourceScreenshots: string[];
}

// A real-world event reconstructed from the evidence (e.g. a process execution,
// logon, file write) with the timestamp it actually happened — distinct from the
// capture/analysis timeline above. These form the chronological attack story.
export interface ForensicEvent {
  id: string;
  timestamp: string;            // the event's real time as observed in the artifact (best effort)
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  relatedFindingIds: string[];
  sourceScreenshots: string[];
  count?: number;               // occurrences when this event aggregates many collapsed lines (e.g. 20); absent ⇒ 1
  endTimestamp?: string;        // time of the last occurrence when aggregated (timestamp is the first)
  // Structured identifiers used to CORRELATE the same real-world artifact across tools
  // (e.g. a Velociraptor alert and a THOR alert about the same downloaded file).
  sha256?: string;
  md5?: string;
  path?: string;                // file path the event concerns (normalized lowercased for matching)
  asset?: string;               // host/computer/FQDN this event pertains to (the affected asset)
  sources?: string[];           // distinct tools/imports that reported this event (corroboration)
  // The specific artifact/source-tool identifier that produced this event, at a finer grain than
  // `sources` (e.g. "Windows.NTFS.MFT" vs "Windows.Detection.Sigma" — both would otherwise show as
  // just "Velociraptor"). Set only by importers that know it (currently velociraptorImport.ts);
  // used by the super-timeline's origin filter (analysis/superTimeline.ts) so a raw artifact
  // row and the detection built from it can be told apart and filtered independently.
  artifactName?: string;
  // Full, untruncated event message/detail (e.g. the raw EVTX rendered Message or ScriptBlock
  // text). `description` is a truncated title/summary; `message` carries the complete text so the
  // super-timeline row can reveal it expandably. Set by importers that have the extra text
  // (currently velociraptorImport.ts); optional — only set when it adds beyond `description`.
  message?: string;
  // Deep-link back to the originating Velociraptor hunt/flow in the Velociraptor GUI. Built at
  // import time from the client's gui-url config; every event from one flow/hunt shares it. Optional.
  veloUrl?: string;
  // Process-chain fields (for RockyRaccoon parent→child validation). processName/parentName
  // are filled by importers that know them (e.g. THOR ProcessCheck); chainCheck is set by
  // the validation pass when enrichment is on.
  processName?: string;
  parentName?: string;
  // Process id of the SUBJECT process — set by importers on process-CREATION events (ECAR
  // PROCESS/CREATE, Windows Security 4688 NewProcessId, Sysmon EID 1 ProcessId). Used for
  // cross-tool correlation: the same creation seen by the EDR and the Windows log merges on
  // (asset + pid) within a time window (correlate.ts step 3), so it carries both tools as sources.
  pid?: number;
  chainCheck?: ProcessChainCheck;
  // File-lineage / network-flow fields (Phase 2 evidence-chain edges).
  // action distinguishes a file write from an execute (same hash → lineage edge) and
  // network sends/receives (srcIp/dstIp/port → network-flow edge).
  action?: "write" | "execute" | "network_send" | "network_receive";
  srcIp?: string;    // source IP for network connections
  dstIp?: string;    // destination IP for network connections
  port?: number;     // destination port
  // Deobfuscated command line (issue #97). Set by the deterministic deobfuscation pass when the
  // event's description contains a base64-encoded or otherwise obfuscated command.
  deobfuscated?: {
    decoded: string;   // the decoded/deobfuscated payload
    method: string;    // how it was decoded: "powershell-enc" | "base64"
    iocs: string[];    // canonical IOC ids (i###) extracted from the decoded content
  };
}

// Result of validating a parent→child process relationship against behavioral intel
// (RockyRaccoon). `observed: false` on a real chain is an anomaly worth surfacing.
export interface ProcessChainCheck {
  observed: boolean;
  note: string;                 // human summary, e.g. "excel.exe → powershell.exe NOT observed"
  link?: string;
  checkedAt: string;
}

export interface Technique {
  id: string;            // e.g. "T1059.001"
  name: string;
  findingIds: string[];
}

export type QuestionStatus = "answered" | "partial" | "unknown";

// A standard DFIR question the AI tracks across the case, with its current answer
// and a pointer to where the investigator can find/confirm it (or what to collect).
export interface InvestigationQuestion {
  id: string;
  question: string;            // "What was the initial access vector?"
  status: QuestionStatus;
  answer: string;              // current best answer, or "" if unknown
  pointer: string;             // where to look: finding ids / event times / screenshots, or what to collect next
  pinned?: boolean;            // analyst-added (via Ask) — preserved across synthesis, which may answer it later
}

export type StepPriority = "critical" | "high" | "medium" | "low";

// A concrete, prioritized recommendation for what to do NEXT — the most valuable
// thing to validate or find out given everything currently known about the case.
export interface NextStep {
  id: string;
  priority: StepPriority;
  action: string;              // what to do, e.g. "Pull Security.evtx 4624/4672 on ALClient07"
  rationale: string;           // why it matters now — what it confirms or rules out
  pointer: string;             // concrete artifact/host/finding to act on, or data to collect
}

export interface InvestigationState {
  caseId: string;
  findings: Finding[];
  iocs: IOC[];
  openThreads: Thread[];
  timeline: TimelineEntry[];           // capture/analysis timeline (what was reviewed, when)
  forensicTimeline: ForensicEvent[];   // real incident events, sorted by their true time
  mitreTechniques: Technique[];
  keyQuestions: InvestigationQuestion[]; // standard DFIR questions + current answers
  nextSteps: NextStep[];               // AI-recommended next investigative actions, most important first
  lastSummary: string;
  attackerPath: string;                // narrative reconstruction of the attacker's path
  narrativeTimeline: string;           // prose story of the incident for stakeholders (re-generated on synthesis)
  updatedAt: string;
}

export function emptyState(caseId: string): InvestigationState {
  return {
    caseId,
    findings: [],
    iocs: [],
    openThreads: [],
    timeline: [],
    forensicTimeline: [],
    mitreTechniques: [],
    keyQuestions: [],
    nextSteps: [],
    lastSummary: "",
    attackerPath: "",
    narrativeTimeline: "",
    updatedAt: new Date(0).toISOString(),
  };
}
