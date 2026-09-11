import type { IocExcludeRule } from "./iocExclude.js";
import type { CanonicalEventEnvelope } from "./canonicalEvent.js";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

// Canonical severity ranking — lower number = more severe. The single table every sort/compare on
// Severity must use (severityFloor, correlate, assetGraph, reports…). forensicGate.ts, notifications.ts
// and slashCommand.ts deliberately keep their own INVERTED (higher = more severe) encodings.
export const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// Worst-wins comparator over the canonical table (ties keep `a`). The single copy every
// severity floor/rollup must use — siemImport re-exports it as `worst` for the importer tier.
export function worstSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a;
}
export type FindingStatus = "open" | "confirmed" | "dismissed";

// Attack outcome as TWO orthogonal axes, never one verdict (#930 item 8). A blocked attack used to
// have nowhere to go: either dismissed (wrong — the detection was right) or left open at High
// (wrong — it did not succeed). #935 fixed four shipped instances of that conflation.
//
// Why two fields and not one "outcome": a finding aggregates several events, and a real chain can
// contain BOTH an execution and a later control action — a payload that ran and was then
// quarantined. One scalar forces a choice between "prevented" (false containment: it ran) and
// "observed" (loses the fact that a control acted). The IR-200 material this comes from treats
// the sequence detected → blocked/allowed/removed → retry → execution as the whole point.
//
//   execution — was the malicious action ITSELF observed? A process start supports execution, not
//               that the payload achieved its objective. `not-observed` is a claim of absence and
//               needs the coverage to back it; `unknown` is the honest default.
//   control   — what did a security control do, if anything? The five named values are the
//               source's own taxonomy for a Defender action event: detected only (none-observed),
//               blocked, allowed, removed (remediated), or unsuccessfully remediated.
//
// Authorization (was this sanctioned?) and detection correctness (did the rule misfire?) are NOT
// here — they are already the false-positive reasons `authorized-test` / `known-good-tool` and
// `detection-misfire`. Confidence stays `confidence`. Status stays `status`.
//
// The fields on Finding are MACHINE-set (a deterministic producer, recomputed every run) and are
// therefore wiped and rebuilt by synthesis like every other conclusion. The analyst's own
// statement lives in the finding-outcome side store (findingOutcome.ts) and is applied over these
// at read time — analyst wins — so a re-synthesis never erases what a human decided.
export const EXECUTION_OUTCOMES = ["observed", "not-observed", "unknown"] as const;
export type ExecutionOutcome = (typeof EXECUTION_OUTCOMES)[number];
export const CONTROL_DISPOSITIONS = [
  "blocked",
  "remediated",
  "remediation-failed",
  "allowed",
  "none-observed",
  "unknown",
] as const;
export type ControlDisposition = (typeof CONTROL_DISPOSITIONS)[number];
export type OutcomeSource = "analyst" | "machine";

// Where a row's evidence came from (#932 item 5). Absent = an observation from the incident: a host
// artifact, a log line, a cloud audit record. `lab` = produced by detonating a sample in a sandbox,
// which says what the FILE does, not what happened on any host. Lab rows never enter the forensic
// timeline: ingest appends them straight to the super-timeline, correlation refuses to union a lab
// row with a host row, and the model learns about the sample through `labIntel` on the sighting
// event that actually carries the hash. The one contamination this exists to end was a KAPE "file
// created X.exe" at Info unioned by hash with a CAPE "injects into explorer.exe" at High — the merge
// made the sandbox row primary, and a real host event was suddenly described as an injection.
export type EvidenceOrigin = "lab";

// One sandbox detonation of one sample, as recorded in `InvestigationState.labIntel` and rendered on
// each incident event that carries the same sha256. Keyed by (sha256, source, runId).
export interface LabIntelRecord {
  sha256: string; // normalised: trimmed, lowercased, exactly 64 hex — or the record is not written
  source: string; // "CAPEv2" | "Falcon Sandbox"
  runId: string; // the report's own analysis/job id; "" when the report has none
  verdict: "malicious" | "suspicious" | "unknown";
  score: number; // the sandbox's own scale, as reported (CAPE 0-10, Falcon 0-100)
  family: string; // malware family the sandbox named, or ""
  signatures: string[]; // behavioural signature names, capped at 5, in the report's order
  detonatedAt: string; // the run's start time, normalised; "" when unknown
  importedAt: string;
}

// A dismissed finding (e.g. a confirmed false positive) keeps its ORIGINAL `severity` as an audit
// trail of what the AI/backfill pass first claimed — see the comment on Finding.severity's sibling
// grounding fields. But every severity-sorted or severity-filtered surface (dashboard panel, Markdown
// report, presentation deck, CSV export…) must stop treating a dismissed Critical as an open Critical,
// or triage-by-severity keeps surfacing resolved noise ahead of genuine open findings (INC-2026-018:
// f8, a confirmed Velociraptor.exe self-signature-collision FP, stayed severity="Critical" after
// dismissal). Call this everywhere severity drives sort order, a filter threshold, a badge, or a
// count — never read `finding.severity` directly for those purposes.
export function getEffectiveSeverity(finding: Pick<Finding, "severity" | "status">): Severity {
  return finding.status === "dismissed" ? "Info" : finding.severity;
}
export type ThreadStatus = "open" | "closed";

// One threat-intel lookup result for an IOC (VirusTotal, MalwareBazaar, AbuseIPDB…).
export interface IocEnrichment {
  source: string; // display label, e.g. "VirusTotal" | "MalwareBazaar" | "ThreatFox"
  provider?: string; // owning provider name (e.g. "Hunting.ch") when it differs from `source` — a fan-out provider emits several sources; dedup/re-check key on this, falling back to `source`
  verdict: "malicious" | "suspicious" | "harmless" | "unknown";
  score?: string; // human summary, e.g. "52/73 detections", "100% abuse"
  detections?: number; // malicious engine count (where applicable)
  total?: number;
  tags?: string[]; // malware family / classification labels
  link?: string; // permalink to the report
  fetchedAt: string; // ISO time the lookup was made
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
  enrichments?: IocEnrichment[]; // threat-intel HITS (added by the enrich pass)
  enrichedBy?: string[]; // provider names that have CHECKED this IOC (hit or not) — so a newly-enabled provider re-checks every IOC, and checked ones aren't re-queried
  // Case-scoped forensic-event id(s) this IOC was authoritatively extracted from (set by the 5
  // priority importers via pipeline.ts). Absent/empty ⇒ iocProvenanceChain.ts falls back to
  // matching by value, same as before this field existed.
  extractedFrom?: string[];
  // Near-duplicate values folded onto this IOC by an analyst merge (#82, iocMerge.ts) — e.g.
  // "evil.com" merged into "www.evil.com". Kept so value-keyed lookups (assetGraph's byValue,
  // event sha256/md5/path matching) still resolve the old value onto this canonical IOC.
  aliasValues?: string[];
  // Human annotation that used to be concatenated into `value` (#177) — the host label in
  // "10.10.20.15 (DC01)", a descriptive suffix, an observed port. Split out at ingest by
  // iocValue.ts so `value` stays the bare indicator (strict consumers like MISP reject anything
  // else) while the context survives: exports carry it in their comment/annotation field.
  note?: string;
}

// Deterministic corroboration rollup for a finding (investigation-guidance #6), computed post-synthesis
// from its supporting in-scope events + related IOCs. Lets the UI/report show "2 tools / 3 hosts / intel"
// vs "uncorroborated", and drives the confidence caps — an unverifiable AI-emitted number alone let a
// single stale CTI verdict mint a Critical finding (northpeak).
export interface FindingCorroboration {
  distinctTools: number; // union of event.sources across the finding's supporting events
  distinctHosts: number; // distinct event.asset across them
  intelSources: number; // this finding's related IOCs carrying a malicious/suspicious intel verdict
  graphLinked: boolean; // any supporting event participates in an evidence-graph causal edge
  // Issue #61 — three additional deterministic confidence signals, all computed in
  // groundAndScoreFindings and optional so findings persisted before they existed still validate:
  verdictFirst?: boolean; // ≥1 supporting event is a graded (Low+) detection — a tool adjudicated it
  huntArtifactOnly?: boolean; // grounded, but EVERY supporting event is Info telemetry (raw collection) — penalised
  kevLinked?: boolean; // a CISA-KEV (actively-exploited) CVE appears in the finding, its events, or its IOCs
}

export interface Finding {
  id: string;
  severity: Severity;
  confidence?: number; // 0–100: AI certainty this finding is real (absent = unknown)
  confidenceReason?: string; // one-sentence why (evidence strength, source corroboration, model certainty)
  // Set post-synthesis by groundAndScoreFindings (investigation-guidance #6). `ungrounded` = no cited
  // in-scope event supports it (a hypothesis, not a fact) → confidence hard-capped + badged.
  // `corroboration` is the rollup above. Both recomputed every synthesis; persisted for display.
  ungrounded?: boolean;
  // A subtler ungroundedness than `ungrounded`: the finding cites REAL in-scope events (so the id-existence
  // check above passes), but names a specific IP address in its own title/description that never appears in
  // the text of any of those cited events — i.e. the claim's content doesn't match its own evidence. Set
  // post-synthesis by groundAndScoreFindings; High/Critical severity is floored to Medium and confidence
  // capped when this fires (investigation-guidance follow-up, veridia-deep-pass 2026-07-22).
  contentMismatch?: boolean;
  // A High/Critical LATERAL-MOVEMENT finding whose named destination host has NO independently-confirmed
  // malicious activity of its own (no High/Critical event on that host in scope) and whose cited evidence
  // is only benign authentication telemetry (no High/Critical supporting event, not graph-linked) — the
  // claim rests on an ordinary logon by a compromised-but-also-legitimate account, not on the attack.
  // Set post-synthesis by groundAndScoreFindings; High/Critical is floored to Medium and confidence capped
  // when it fires (meridian-tax-ransomware benchmark 2026-07-23: kevin.obrien's own WS-17 session and an
  // uninvolved user's WS-09 logon were both fabricated into "RDP lateral movement"; the deep pass then
  // HARDENED the WS-17 one from confidence 45 → 82 by citing the real-but-benign logon).
  lateralUnconfirmed?: boolean;
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
  // Stable, wording-resilient identity for cross-run matching (issue #69): dominant ATT&CK technique
  // + an order-independent noun phrase from the title, e.g. "T1059.001:encoded_powershell". Set
  // post-synthesis by groundAndScoreFindings (deriveSemanticKey); used as the primary second-opinion
  // delta key so a trivial rewording no longer registers as a new finding. Optional — findings
  // synthesized before this field existed fall back to the normalized title.
  semanticKey?: string;
  description: string;
  relatedIocs: string[]; // IOC ids
  sourceScreenshots: string[]; // screenshot filenames
  mitreTechniques: string[]; // technique ids, e.g. "T1059"
  // Forensic-event ids this finding cites as its supporting evidence (issue #222 — cited AI
  // answers). Only synthesis populates it (extraction can't know finding ids yet); optional so
  // findings persisted before this field existed still validate.
  relatedEventIds?: string[];
  firstSeen: string;
  lastUpdated: string;
  status: FindingStatus;
  // Attack outcome axes — see the EXECUTION_OUTCOMES comment. Absent = nothing has said. Machine-set
  // here; the analyst's statement is applied over these from the side store. Provenance is PER AXIS:
  // an analyst who overrides only execution has said nothing about control, and a report that
  // attributed both to them would corrupt provenance in a forensic deliverable.
  execution?: ExecutionOutcome;
  control?: ControlDisposition;
  executionSource?: OutcomeSource;
  controlSource?: OutcomeSource;
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
  timestamp: string; // the event's real time as observed in the artifact (best effort)
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  relatedFindingIds: string[];
  sourceScreenshots: string[];
  // Versioned structured envelope (#374). Legacy display/correlation fields remain during the
  // incremental migration, but identity-aware consumers read this envelope so prose wording is
  // never their data contract. StateStore upgrades older events on read without removing fields.
  canonical?: CanonicalEventEnvelope;
  count?: number; // occurrences when this event aggregates many collapsed lines (e.g. 20); absent ⇒ 1
  endTimestamp?: string; // time of the last occurrence when aggregated (timestamp is the first)
  // Clock-skew projection (#228), set ONLY on read-path copies while timeline alignment is on and
  // stripped before anything derived from them is persisted (analysis/clockSkew.ts). When present,
  // `timestamp` is the aligned (virtual) time and `originalTimestamp` is what the artifact actually
  // recorded — the report and the UI must show the recorded time alongside the corrected one, since
  // only the former is evidence.
  originalTimestamp?: string;
  skewOffsetMs?: number; // correction applied: recorded − aligned
  // TRUE when the YEAR in `timestamp` was GUESSED by the importer rather than read out of the
  // record. An RFC 3164 syslog / Cisco ASA / Snort line carries no year at all, and the AI log/CSV
  // imports infer one from context; every other importer reads an explicit year (EVTX, RFC 3339,
  // a Velociraptor artifact field). Only events marked here may be re-anchored by clampOutlierYears
  // (#739) — a real minority-year event whose year came out of the record is EVIDENCE, and rewriting
  // it to match the import's majority year silently destroys it.
  yearInferred?: boolean;
  // What `timestamp` said BEFORE clampOutlierYears re-anchored its year. Set only on events the
  // clamp actually rewrote, and never overwritten once set, so the adjustment stays auditable and
  // the UI can show the analyst which times are machine-adjusted rather than recorded (#739).
  yearClampedFrom?: string;
  // Structured identifiers used to CORRELATE the same real-world artifact across tools
  // (e.g. a Velociraptor alert and a THOR alert about the same downloaded file).
  sha256?: string;
  md5?: string;
  path?: string; // file path the event concerns (normalized lowercased for matching)
  asset?: string; // host/computer/FQDN this event pertains to (the affected asset)
  sources?: string[]; // distinct tools/imports that reported this event (corroboration)
  // The specific artifact/source-tool identifier that produced this event, at a finer grain than
  // `sources` (e.g. "Windows.NTFS.MFT" vs "Windows.Detection.Sigma" — both would otherwise show as
  // just "Velociraptor"). Set only by importers that know it (currently velociraptorImport.ts);
  // used by the super-timeline's origin filter (analysis/superTimeline.ts) so a raw artifact
  // row and the detection built from it can be told apart and filtered independently.
  artifactName?: string;
  // Identity of the ONE underlying log record this event was mapped from, when the importer knew
  // it: `evtx:<channel>:<EventRecordID>` for a Windows event log. Two DIFFERENT parsers reading the
  // same EVTX file mint the same value, so correlate.ts can recognise a Hayabusa row and a Chainsaw
  // row as one observation and merge them instead of doubling the timeline (#688). Never set on an
  // aggregated event — a collapsed group stands for many records, not one.
  sourceRecordId?: string;
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
  // Full command line of the SUBJECT process on a process-creation event (Sysmon EID 1 CommandLine,
  // Security 4688 CommandLine, ECAR PROCESS/CREATE, auditd proctitle, journald _CMDLINE). Set by
  // importers that parse it; when absent, correlate.ts scrapes it from description/message as a
  // fallback. Used for cross-tool correlation of the SAME creation when the tools assign different
  // pids and share no hash (correlate.ts step 4). (#68)
  commandLine?: string;
  // Stable, TIME-INDEPENDENT identity of a process creation: a hash of
  // shortHost|processName|parentName|normalizedCommandLine. correlate.ts groups pid-bearing events by
  // this and applies the time window separately (like host+pid), so two tools reporting the same
  // creation seconds apart merge while a later re-run of the same command stays distinct. Time is
  // deliberately excluded from the signature so events straddling a bucket boundary still match. (#68)
  chainSignature?: string;
  chainCheck?: ProcessChainCheck;
  // File-lineage / network-flow fields (Phase 2 evidence-chain edges).
  // action distinguishes a file write from an execute (same hash → lineage edge) and
  // network sends/receives (srcIp/dstIp/port → network-flow edge).
  action?: "write" | "execute" | "network_send" | "network_receive";
  srcIp?: string; // source IP for network connections
  dstIp?: string; // destination IP for network connections
  port?: number; // destination port
  // Deobfuscated command line (issue #97). Set by the deterministic deobfuscation pass when the
  // event's description contains a base64-encoded or otherwise obfuscated command.
  deobfuscated?: {
    decoded: string; // the decoded/deobfuscated payload
    method: string; // the OUTERMOST layer, kept for compatibility with single-layer results
    iocs: string[]; // canonical IOC ids (i###) extracted from the decoded content
    // Every layer peeled, outermost first (#909 item 2). An analyst has to be able to see HOW a
    // payload was reached before trusting what it says.
    steps?: { method: string; detail?: string }[];
    // A limit was hit (depth, size, time) or an expression could not be folded without executing
    // it. Partial output is shown as partial — never as the final answer.
    partial?: boolean;
    // The decoder that produced this. Improving the decoder does not retroactively improve stored
    // results, so this is what lets a later pass find the stale ones and redo them deliberately.
    version?: number;
  };
  // The modification time the SOURCE ARTIFACT recorded for this file (#909 item 8).
  //
  // Structured rather than only in the description, because corroborating a timestomp means
  // comparing what two independent artifacts say about ONE file, and reading either value back out
  // of prose would be parsing a sentence to make a forensic claim. ShimCache keeps its copy in the
  // registry and the MFT keeps its own; a disagreement between them is the corroboration.
  fileModified?: string;
  // Provenance markers explaining WHY this event was pulled into the analyzed timeline by an automated
  // pass rather than a normal import — currently the second-look loop (guidance #11), which stamps
  // "[second-look: h2]" onto a raw super-timeline row it promoted to resolve an open hypothesis/question.
  // Rendered as a small chip on the timeline row so the analyst sees the row is machine-surfaced.
  provenance?: string[];
  // See EvidenceOrigin. Set by the sandbox importer on every row it emits; absent everywhere else.
  origin?: EvidenceOrigin;
  // The lab detonations of THIS event's sample, derived at merge time from InvestigationState.labIntel
  // by sha256 — never stored as a claim of its own, cleared and recomputed on every merge. Rendered to
  // the model as a <sandbox:…> tag beside <host:…>, so it reads "the sample seen here did X in a lab".
  labIntel?: LabIntelRecord[];
}

// Result of validating a parent→child process relationship against behavioral intel
// (RockyRaccoon). `observed: false` on a real chain is an anomaly worth surfacing.
export interface ProcessChainCheck {
  observed: boolean;
  note: string; // human summary, e.g. "excel.exe → powershell.exe NOT observed"
  link?: string;
  checkedAt: string;
}

export interface Technique {
  id: string; // e.g. "T1059.001"
  name: string;
  findingIds: string[];
  // The ANALYST added this one, by accepting a second-opinion mitre_added delta.
  //
  // The projection shows a technique only while surviving evidence still backs it — a finding that
  // is still there, or an event still carrying the id (#893). An accepted addition has neither by
  // construction: it is the analyst overruling both models, so nothing in the case points at it and
  // it would vanish the moment they accepted it. Their decision IS the support.
  //
  // A record of a human choice, not derived provenance: it never has to be re-derived, kept in step
  // with the timeline, or reconciled through correlation, so it does not reintroduce what #893
  // removed. `mitre_removed` still deletes the row outright.
  analystAccepted?: true;
}

// A STRUCTURED collection directive (investigation-guidance #8). The synthesis prompt already asks the
// model to name what to collect and where — but only as free prose in `pointer`, which nothing can act
// on. This captures the same intent as fields so the UI can attach a one-click Velociraptor Deploy
// button, the playbook can task it against the right endpoint, and a later import can be matched to it.
// Every field optional/best-effort so an older state or a partial model reply still validates.
export interface CollectDirective {
  host?: string; // the endpoint to collect from (validated against the case's known endpoints before deploy)
  artifact?: string; // the artifact/tool to collect, e.g. "Windows.EventLogs" or "$MFT"
  logSource?: string; // the log source/channel/file, e.g. "Security.evtx 4624/4672", "web proxy logs"
  expectedOutcome?: string; // what a positive result would show — ties the collection to the question/hypothesis it serves
}

export type QuestionStatus = "answered" | "partial" | "unknown";

// A standard DFIR question the AI tracks across the case, with its current answer
// and a pointer to where the investigator can find/confirm it (or what to collect).
export interface InvestigationQuestion {
  id: string;
  question: string; // "What was the initial access vector?"
  status: QuestionStatus;
  answer: string; // current best answer, or "" if unknown
  pointer: string; // where to look: finding ids / event times / screenshots, or what to collect next
  pinned?: boolean; // analyst-added (via Ask) — preserved across synthesis, which may answer it later
  // Finding ids this answer relies on (set by synthesis). Lets a later re-synthesis detect when a
  // supporting finding was marked false-positive and force the question back to "unknown" instead
  // of silently keeping a stale answer — see applyFalsePositive/reconsiderKeyQuestions in pipeline.ts.
  relatedFindingIds?: string[];
  // Deterministic contradiction flag (investigation-guidance #3): set when the answer asserts an
  // ABSENCE ("no data exfiltration confirmed") but in-scope events carry the matching ATT&CK
  // techniques — the timeline contradicts the answer. Set post-synthesis by flagContradictedAnswers;
  // the UI/report render it as a "contradicted by timeline evidence" badge. Absent = no contradiction.
  contradicted?: {
    techniques: string[]; // the contradicting technique ids observed in-scope
    eventIds: string[]; // the events that carry them (a few, for the pointer/badge)
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
  action: string; // what to do, e.g. "Pull Security.evtx 4624/4672 on ALClient07"
  rationale: string; // why it matters now — what it confirms or rules out
  pointer: string; // concrete artifact/host/finding to act on, or data to collect
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

// Structured analytical-uncertainty status (issue #73). A DFIR analytical-safety guard: separates what
// the analysis KNOWS from what it INFERRED from what it merely SPECULATED, so an inferred conclusion is
// never read as a confirmed fact. Distinct from `hypotheses` (competing explanations to test) — an
// uncertainty is a single claim/topic with an explicit epistemic status and the gap needed to resolve it.
export const UNCERTAINTY_STATUSES = ["confirmed", "inferred", "speculated", "unknown"] as const;
export type UncertaintyStatus = (typeof UNCERTAINTY_STATUSES)[number];

export interface Uncertainty {
  topic: string; // the claim/aspect this refers to, e.g. "initial access vector"
  status: UncertaintyStatus; // confirmed (evidenced) | inferred | speculated | unknown
  basis: string; // what the current status rests on — supporting event ids / findings (prose)
  gap: string; // what is missing to raise the status (the collection/analysis needed)
}

export interface InvestigationState {
  caseId: string;
  findings: Finding[];
  iocs: IOC[];
  openThreads: Thread[];
  timeline: TimelineEntry[]; // capture/analysis timeline (what was reviewed, when)
  forensicTimeline: ForensicEvent[]; // real incident events, sorted by their true time
  mitreTechniques: Technique[];
  keyQuestions: InvestigationQuestion[]; // standard DFIR questions + current answers
  nextSteps: NextStep[]; // AI-recommended next investigative actions, most important first
  uncertainties: Uncertainty[]; // structured "what we know vs inferred vs speculated" ledger (#73)
  lastSummary: string;
  attackerPath: string; // narrative reconstruction of the attacker's path
  narrativeTimeline: string; // prose story of the incident for stakeholders (re-generated on synthesis)
  // Per-case domain/hostname (or any IOC type) exclude rules — a match is deleted from `iocs`
  // outright and never re-created by a future import/AI-synthesis delta (see mergeDelta). Distinct
  // from the global IOC Whitelist, which is reversible and merely marks a match false-positive.
  iocExcludeRules: IocExcludeRule[];
  // Sandbox detonation registry (#932 item 5), keyed by (sha256, source, runId). Optional so state
  // files written before it exist load unchanged. Carried by name through mergeDelta and unioned by
  // key in mergeConcurrentAdditions — a reducer that rebuilds the state object drops what it does not
  // name, which is how an earlier draft of this would have silently lost every record.
  labIntel?: LabIntelRecord[];
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
    uncertainties: [],
    lastSummary: "",
    attackerPath: "",
    narrativeTimeline: "",
    iocExcludeRules: [],
    updatedAt: new Date(0).toISOString(),
  };
}
