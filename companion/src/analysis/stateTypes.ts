import type { IocExcludeRule } from "./iocExclude.js";

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
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "sid" | "other";
  value: string;
  firstSeen: string;
  enrichments?: IocEnrichment[];                               // threat-intel HITS (added by the enrich pass)
  enrichedBy?: string[];                                       // provider names that have CHECKED this IOC (hit or not) — so a newly-enabled provider re-checks every IOC, and checked ones aren't re-queried
  // Case-scoped forensic-event id(s) this IOC was authoritatively extracted from (set by the 5
  // priority importers via pipeline.ts). Absent/empty ⇒ iocProvenanceChain.ts falls back to
  // matching by value, same as before this field existed.
  extractedFrom?: string[];
}

// Deterministic corroboration rollup for a finding (investigation-guidance #6), computed post-synthesis
// from its supporting in-scope events + related IOCs. Lets the UI/report show "2 tools / 3 hosts / intel"
// vs "uncorroborated", and drives the confidence caps — an unverifiable AI-emitted number alone let a
// single stale CTI verdict mint a Critical finding (northpeak).
export interface FindingCorroboration {
  distinctTools: number;   // union of event.sources across the finding's supporting events
  distinctHosts: number;   // distinct event.asset across them
  intelSources: number;    // this finding's related IOCs carrying a malicious/suspicious intel verdict
  graphLinked: boolean;    // any supporting event participates in an evidence-graph causal edge
  // Issue #61 — three additional deterministic confidence signals, all computed in
  // groundAndScoreFindings and optional so findings persisted before they existed still validate:
  verdictFirst?: boolean;      // ≥1 supporting event is a graded (Low+) detection — a tool adjudicated it
  huntArtifactOnly?: boolean;  // grounded, but EVERY supporting event is Info telemetry (raw collection) — penalised
  kevLinked?: boolean;         // a CISA-KEV (actively-exploited) CVE appears in the finding, its events, or its IOCs
}

export interface Finding {
  id: string;
  severity: Severity;
  confidence?: number;          // 0–100: AI certainty this finding is real (absent = unknown)
  confidenceReason?: string;    // one-sentence why (evidence strength, source corroboration, model certainty)
  // Set post-synthesis by groundAndScoreFindings (investigation-guidance #6). `ungrounded` = no cited
  // in-scope event supports it (a hypothesis, not a fact) → confidence hard-capped + badged.
  // `corroboration` is the rollup above. Both recomputed every synthesis; persisted for display.
  ungrounded?: boolean;
  corroboration?: FindingCorroboration;
  // Rabbit-hole detection (investigation-guidance #13). `relevance` places the finding relative to the
  // corroborated main attack path: 'connected' (on it) → a lead; 'disconnected' (evidence sits in a
  // separate graph component) → a possible rabbit hole; 'unrelated-but-real' (AI: genuine but a separate
  // issue) → parked; 'undetermined' (evidence not in the causal graph, or unscored). `connectedness` is
  // the 0–1 fraction of the finding's graph-modeled evidence that touches the main component.
  // `relevanceDiscriminator` (disconnected only) names what to look for to tie it into the attack path.
  // All recomputed every synthesis by scoreFindingsRelevance; persisted for display/grouping.
  relevance?: "connected" | "disconnected" | "unrelated-but-real" | "undetermined";
  connectedness?: number;
  relevanceDiscriminator?: string;
  title: string;
  description: string;
  relatedIocs: string[];        // IOC ids
  sourceScreenshots: string[];  // screenshot filenames
  mitreTechniques: string[];    // technique ids, e.g. "T1059"
  // Forensic-event ids this finding cites as its supporting evidence (issue #222 — cited AI
  // answers). Only synthesis populates it (extraction can't know finding ids yet); optional so
  // findings persisted before this field existed still validate.
  relatedEventIds?: string[];
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
  // Provenance markers explaining WHY this event was pulled into the analyzed timeline by an automated
  // pass rather than a normal import — currently the second-look loop (guidance #11), which stamps
  // "[second-look: h2]" onto a raw super-timeline row it promoted to resolve an open hypothesis/question.
  // Rendered as a small chip on the timeline row so the analyst sees the row is machine-surfaced.
  provenance?: string[];
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

// A STRUCTURED collection directive (investigation-guidance #8). The synthesis prompt already asks the
// model to name what to collect and where — but only as free prose in `pointer`, which nothing can act
// on. This captures the same intent as fields so the UI can attach a one-click Velociraptor Deploy
// button, the playbook can task it against the right endpoint, and a later import can be matched to it.
// Every field optional/best-effort so an older state or a partial model reply still validates.
export interface CollectDirective {
  host?: string;            // the endpoint to collect from (validated against the case's known endpoints before deploy)
  artifact?: string;        // the artifact/tool to collect, e.g. "Windows.EventLogs" or "$MFT"
  logSource?: string;       // the log source/channel/file, e.g. "Security.evtx 4624/4672", "web proxy logs"
  expectedOutcome?: string; // what a positive result would show — ties the collection to the question/hypothesis it serves
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
  // Finding ids this answer relies on (set by synthesis). Lets a later re-synthesis detect when a
  // supporting finding was marked false-positive and force the question back to "unknown" instead
  // of silently keeping a stale answer — see applyFalsePositive/reconsiderKeyQuestions in pipeline.ts.
  relatedFindingIds?: string[];
  // Deterministic contradiction flag (investigation-guidance #3): set when the answer asserts an
  // ABSENCE ("no data exfiltration confirmed") but in-scope events carry the matching ATT&CK
  // techniques — the timeline contradicts the answer. Set post-synthesis by flagContradictedAnswers;
  // the UI/report render it as a "contradicted by timeline evidence" badge. Absent = no contradiction.
  contradicted?: {
    techniques: string[];   // the contradicting technique ids observed in-scope
    eventIds: string[];     // the events that carry them (a few, for the pointer/badge)
  };
  // Structured collection directive for an 'unknown'/'partial' question (investigation-guidance #8):
  // where/what to collect to answer it, so the UI can offer a one-click Deploy and a later import can be
  // matched back to it. Complements the free-text `pointer`.
  collect?: CollectDirective;
  // Immediate FP cascade (investigation-guidance #12): set by reconsiderKeyQuestions when the FP-mark
  // route synchronously reset this question because a supporting finding was just rejected — the answer
  // is neutralized NOW and this badges "stale — re-synthesis queued" until the background re-synthesis
  // recomputes the authoritative answer (which clears the flag). Absent = current.
  staleReSynth?: boolean;
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
  // Structured collection directive (investigation-guidance #8): the machine-actionable form of a
  // collection-type step, so the UI can attach a one-click Velociraptor Deploy and a later import can
  // be matched to it. Absent for non-collection steps (e.g. "sandbox-detonate X").
  collect?: CollectDirective;
  // Finding ids this step advances, so the playbook can link it without prose-scraping "f<n>" tokens.
  relatedFindingIds?: string[];
  // Immediate FP cascade (investigation-guidance #12): set when the FP-mark route detected this step
  // advances a finding that was just rejected — badged "stale" until the re-synthesis rewrites the list.
  staleReSynth?: boolean;
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
  // Per-case domain/hostname (or any IOC type) exclude rules — a match is deleted from `iocs`
  // outright and never re-created by a future import/AI-synthesis delta (see mergeDelta). Distinct
  // from the global IOC Whitelist, which is reversible and merely marks a match false-positive.
  iocExcludeRules: IocExcludeRule[];
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
    iocExcludeRules: [],
    updatedAt: new Date(0).toISOString(),
  };
}
