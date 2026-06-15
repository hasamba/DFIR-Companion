import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join as joinPath } from "node:path";
import { createHash } from "node:crypto";
import { z } from "zod";
import type { AIProvider, AnalyzeImage, AnalyzeRequest, AnalyzeResult } from "../providers/provider.js";
import { createConsoleLogger, normalizeLogLevel, type Logger } from "../logging/logger.js";
import { createAnonymizer, deriveKnownEntities, type CustomEntity } from "./anonymize.js";
import { toAnonPolicy, type AnonControlStore } from "./anonControl.js";
import type { CustomEntitiesStore } from "./anonEntities.js";
import type { DiscoveredEntitiesStore } from "./anonDiscovered.js";
import type { CaptureMetadata } from "../types.js";
import type { StateStore } from "./stateStore.js";
import type { InvestigationState, InvestigationQuestion, ForensicEvent, Severity } from "./stateTypes.js";
import { deltaSchema, askSchema, execSummarySchema, type AskAnswer, type ExecSummary } from "./responseSchema.js";
import { buildStateSummary } from "./summary.js";
import { mergeDelta } from "./stateMerge.js";
import { applySeverityFloor } from "./severityFloor.js";
import { parseJsonLoose } from "./extractJson.js";
import { applyLegitimate, buildLegitimateContext, filterLegitimateEvents, type LegitimateStore } from "./legitimate.js";
import { backfillHighSeverityFindings } from "./highSeverityFindings.js";
import { detectTimelineGaps, backfillSilenceGapFindings, gapEnvOptions } from "./gapDetect.js";
import {
  gapHypothesesResponseSchema,
  sanitizeGapHypotheses,
  buildGapHypotheses,
  surroundingEvents,
  renderGapsForPrompt,
  hasGapMaterial,
  GAP_HYPOTHESIS_MAX_DEFAULT,
  SURROUNDING_EVENTS_DEFAULT,
  GAP_HYPOTHESIS_CAVEAT,
  type GapHypothesesResult,
} from "./gapHypothesis.js";
import { SHADOW_ARTIFACTS } from "./shadowArtifacts.js";
import { diffFindings, type FindingsDiff } from "./findingsDiff.js";
import type { SynthMetaStore } from "./synthMeta.js";
import { correlateEvents } from "./correlate.js";
import { detectTool } from "./toolDetect.js";
import { filterEventsByScope, hasScope, NO_SCOPE, type ScopeStore } from "./scope.js";
import { parseCsv, chunkToCsvText } from "./csvImport.js";
import { parseLogLines } from "./logImport.js";
import { aggregateLogLines } from "./logAggregate.js";
import { parseThorReport, type ThorImportOptions } from "./thorImport.js";
import { parseSiemExport, type SiemImportOptions } from "./siemImport.js";
import { parseChainsawReport, type ChainsawImportOptions } from "./chainsawImport.js";
import { parseHayabusaTimeline, type HayabusaImportOptions } from "./hayabusaImport.js";
import { parseVelociraptorJson, type VelociraptorImportOptions } from "./velociraptorImport.js";
import { parseNetworkLogs, type NetworkImportOptions } from "./networkImport.js";
import { parseKapeCsv, type KapeImportOptions } from "./kapeImport.js";
import { parseCybertriage, type CybertriageImportOptions } from "./cybertriageImport.js";
import { parseM365Audit, type M365ImportOptions } from "./m365Import.js";
import { parseCloudTrail, type AwsImportOptions } from "./awsImport.js";
import { parseCloudActivity, type CloudActivityImportOptions } from "./cloudActivityImport.js";
import { parsePlasoCsv, type PlasoImportOptions } from "./plasoImport.js";
import { parseSandboxReport, type SandboxImportOptions } from "./sandboxImport.js";
import { parseMemory, type MemoryImportOptions } from "./memoryImport.js";
import { parseEmail, type EmailImportOptions } from "./emailImport.js";
import { parseTheHive, type TheHiveImportOptions } from "./theHiveImport.js";
import { parseIrisCase, type IrisCaseData, type IrisImportOptions } from "./irisImport.js";
import { parseAuditdLog, type AuditdImportOptions } from "./auditdImport.js";
import { parseJournald, type JournaldImportOptions } from "./journaldImport.js";
import { parseSysdig, type SysdigImportOptions } from "./sysdigImport.js";
import { parseWazuhAlerts, type WazuhImportOptions } from "./wazuhImport.js";
import { selectSynthesisEvents, buildSynthesisContext } from "./synthSelect.js";
import type { KevStore } from "./kevStore.js";
import type { KevCatalog } from "./kev.js";
import {
  huntSuggestionsResponseSchema,
  sanitizeHuntSuggestions,
  renderHuntFindings,
  renderHuntIocs,
  hasHuntMaterial,
  HUNT_SUGGEST_MAX_DEFAULT,
  type HuntSuggestion,
} from "./huntSuggest.js";
import {
  playbookHuntResponseSchema,
  sanitizePlaybookHuntSuggestions,
  buildTaskEndpointsMap,
  knownEndpoints,
  renderPlaybookHuntTasks,
  renderKnownEndpoints,
  renderAvailableArtifacts,
  hasPlaybookHuntMaterial,
  PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT,
  type PlaybookHuntSuggestion,
} from "./playbookHunt.js";
import {
  memoryNextStepResponseSchema,
  sanitizeMemoryNextSteps,
  renderMemoryEvidence,
  memoryPluginsPresent,
  isMemoryEvent,
  hasMemoryMaterial,
  MEMORY_NEXTSTEP_MAX_DEFAULT,
  type MemoryNextStep,
} from "./memoryNextStep.js";
import type { PlaybookTask } from "./playbook.js";
import { estimateTokens, inputTokenBudget, batchByBudget, fitItemsToBudget } from "./promptBudget.js";
import type { AiControlStore } from "./aiControl.js";
import type { NotebookStore } from "./notebookStore.js";
import { ocrRedactImage, type OcrRunner } from "./ocrRedact.js";

// Write a redacted screenshot copy to DFIR_OCR_DEBUG_DIR for visual inspection. The redacted
// buffer keeps the source image format (sharp infers it from the input), so the extension is
// derived from the source mime type. Best-effort: a dump failure must never break analysis, and
// caseId is sanitized so it can't escape the debug dir. This never touches the evidence files.
async function dumpRedactedImage(
  dir: string,
  caseId: string,
  index: number,
  mimeType: string,
  buffer: Buffer,
): Promise<void> {
  try {
    const ext = (mimeType.split("/")[1] ?? "png").replace(/[^a-z0-9]/gi, "") || "png";
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const safeCase = caseId.replace(/[^a-z0-9_-]/gi, "_");
    const outDir = joinPath(dir, safeCase);
    await mkdir(outDir, { recursive: true });
    await writeFile(joinPath(outDir, `${stamp}-img${index + 1}.${ext}`), buffer);
  } catch (err) {
    console.warn(`[OCR dump] ${(err as Error).message}`);
  }
}

export const SYSTEM_PROMPT = [
  "You are a DFIR analyst assistant. You are shown screenshots from a forensic investigation. The",
  "evidence may come from ANY security tool, including: Velociraptor, EDR/XDR consoles (CrowdStrike",
  "Falcon, Microsoft Defender for Endpoint, SentinelOne, Carbon Black), SIEM/log UIs (Splunk, Elastic/",
  "Kibana), VirusTotal, and raw Windows artifacts. Plus a summary of findings already recorded.",
  "Update existing findings by their id; never create a duplicate finding for a topic already",
  "listed. Open a thread for any lead you start chasing and close it by id when resolved.",
  "",
  "CRITICAL — FORENSIC TIMELINE: forensic artifacts on screen carry REAL timestamps (process",
  "create time, file MAC times, logon time, prefetch run time, scheduled-task time, registry",
  "write time, network connection time, etc.). For every dated incident event you can read, emit",
  "a forensicEvents entry whose timestamp is read FROM THAT ROW's OWN time column in the image",
  "(e.g. the 'Timestamp'/'EventTime' column of the results table). EMIT EVERY TIMESTAMP IN UTC —",
  "ISO-8601 with a trailing 'Z'. If the artifact shows a timezone (an offset like +02:00, or an",
  "abbreviation like EST/CEST/UTC+2), CONVERT the time to UTC. If it shows NO timezone, keep the",
  "wall-clock time and just add a trailing 'Z' (forensic tooling overwhelmingly displays UTC) —",
  "never shift a timezone-less time.",
  "NEVER use the screenshot capture time or the current time. If a row has no visible event time,",
  "set its timestamp to an empty string \"\" — do NOT substitute the capture/current time.",
  "These reconstruct WHEN the attack happened on the SYSTEM(S) UNDER INVESTIGATION.",
  "",
  "YOUR PRIMARY JOB — EXTRACT THE ARTIFACT ROWS. Velociraptor/EDR/SIEM tables ARE the evidence.",
  "Extract EVERY data row that represents real host/attacker activity as a forensicEvent, using the",
  "timestamp in that row. This is the most important output — do NOT be shy. High-value rows you must",
  "ALWAYS capture: antivirus / EDR alerts (Microsoft Defender, Sysmon), Security event-log logons,",
  "process executions, network connections, scheduled tasks, services, registry changes, file MAC",
  "times. Example — a Defender 'Operational' row:",
  "  Timestamp 2026-05-26T12:25:36Z | Defender Alert (Severe) | VirTool:Win32/Kekeo.A!MTB |",
  "  Path C:\\Users\\srv\\Downloads\\Rubeus.exe | User ADATUMLAB\\srv",
  "  → forensicEvent: timestamp '2026-05-26T12:25:36Z', severity 'Critical', description",
  "    'Microsoft Defender flagged VirTool:Win32/Kekeo (Rubeus.exe) for user ADATUMLAB\\\\srv at",
  "    C:\\\\Users\\\\srv\\\\Downloads\\\\Rubeus.exe'. Add IOCs (Rubeus.exe, the threat name) and a",
  "    finding (credential-theft tool / Kekeo). NEVER drop a malware/threat detection.",
  "",
  "EDR/XDR & SIEM DETECTIONS ARE EVIDENCE — extract EVERY one. A CrowdStrike Falcon / Defender for",
  "Endpoint / SentinelOne 'detections' view, OR a SIEM alerts view (Splunk notable events / Enterprise",
  "Security, Elastic Security alerts, Microsoft Sentinel incidents, QRadar offenses, a Kibana/Grafana",
  "panel listing security alerts), is a CONSOLE OF FINDINGS — NOT a 'dashboard' to skip. Each detection",
  "/ alert / notable / offense — with its severity, rule/detection name, triggering process / command",
  "line / query, file path, hash, host, user, source/dest IP, and MITRE tactic & technique — IS a real",
  "event: emit it as a forensicEvent AND raise a finding. Use the alert's OWN time as the event time.",
  "Example — a CrowdStrike High detection:",
  "  Jun 1 2026 12:37:35 | High | ShadowMark.exe on ALCLIENT04 by ADATUMLAB\\Srv |",
  "  cmdline '\\\"C:\\\\Users\\\\srv\\\\Desktop\\\\New folder\\\\ShadowMark.exe\\\" /action:add /target:sac1$' |",
  "  SHA256 2eeba4c80a6f91f06784c0c699512c22ff132233c71af336a423414cc84f574a | AI Powered IOA / Malicious File",
  "  → forensicEvent severity 'High', description 'CrowdStrike flagged ShadowMark.exe (High, Malicious",
  "    File / AI IOA) run by ADATUMLAB\\\\Srv on ALCLIENT04: cmdline … /action:add /target:sac1$; parent",
  "    process killed'; IOCs ShadowMark.exe + the SHA256; a finding (suspected machine-account/SAC abuse).",
  "Example — a Splunk notable / Elastic Security alert:",
  "  2026-06-01T09:14:22Z | High | rule 'Brute Force - Multiple Failed Logons' | host ALCLIENT07 |",
  "  user ADATUMLAB\\\\jdoe | src 10.0.0.5 | T1110",
  "  → forensicEvent severity 'High', description 'SIEM rule \\\"Brute Force - Multiple Failed Logons\\\"",
  "    fired for ADATUMLAB\\\\jdoe on ALCLIENT07 from 10.0.0.5'; IOC 10.0.0.5; a finding (brute force,",
  "    T1110). Multiple near-identical detections/alerts collapse into ONE finding, but keep each",
  "    distinct process/host/user/rule as its own event.",
  "",
  "SEVERITY/LEVEL COLUMN — STRONG FINDING SIGNAL. If a row has its own Severity / Level / Criticality",
  "/ Risk / Confidence column and it reads Critical, High, or Severe (or a high numeric score), treat",
  "it as important by default (~90% of the time it IS a finding): (a) ALWAYS emit it as a forensicEvent",
  "with that severity mapped to ours (Severe→Critical, High→High), and (b) ALSO raise a finding for it",
  "in this response — do not wait for the synthesis pass. Only skip the finding if the row is clearly",
  "benign/expected (e.g. an informational rule the client confirmed legitimate). Never silently drop a",
  "Critical/High row.",
  "",
  "DESCRIBE EACH EVENT BY WHAT HAPPENED ON THE SYSTEM, not by the tool you saw it in. Write the",
  "artifact's own facts. WRONG: 'Velociraptor EventLog shows a Defender alert…'. RIGHT: 'Microsoft",
  "Defender flagged Rubeus.exe…'. Do NOT start an event with 'Velociraptor', 'VolWeb', 'the dashboard",
  "shows', or append 'observed in <tool>' — name the host, process, user, IP, etc. instead.",
  "",
  "DO NOT ADD NON-EVENTS. Two things are NOT forensic events (skip them — but never let this cause you",
  "to drop a real artifact row or a detection): (1) operating the tooling / your own workflow — running",
  "a hunt or query, 'EventLog analysis performed', 'Response and Monitoring accessed', 'data",
  "collection', 'analysis completed', clicking/scrolling; (2) the bare act of opening a tool with NO",
  "data on screen — 'Access to VolWeb', 'DFIR Companion dashboard access observed', an empty/loading",
  "panel or login page. This is NARROW: a detections/alerts console FULL of detections or alerts",
  "(CrowdStrike, Defender, SentinelOne, Splunk, Elastic, Sentinel, QRadar, Kibana/Grafana security",
  "panels) is EVIDENCE — extract them, do not dismiss the page as 'navigation'. If a screen names a",
  "process, file, command line, query, hash, host, user, IP, rule/alert name, or threat, it has",
  "content → extract it. NEVER stamp an event with the screenshot capture time — if a row truly has no",
  "time column, use \"\".",
  "",
  "AFFECTED ASSET: for each forensicEvent, set 'asset' to the host/computer/FQDN the event happened",
  "ON — read it from the row's Computer/Hostname/FQDN/Endpoint/Device column, the console's host",
  "field, or the window title (e.g. 'ALCLIENT07', 'dc01.adatumlab.local'). Leave 'asset' as \"\" only",
  "if no host is visible. This ties each indicator to the machine it was seen on.",
  "",
  "ATTACKER PATH: in 'attackerPath', narrate the adversary's progression in kill-chain order",
  "(initial access → execution → persistence → priv-esc → lateral movement → C2 → exfil/impact),",
  "citing finding ids and event times. Refine it as new evidence arrives.",
  "",
  "FINDINGS CONFIDENCE: every finding MUST include a 'confidence' field (integer 0–100) — your",
  "certainty that this is real attacker activity, not a false positive. 95+ = confirmed hit; 70–90 =",
  "strongly suspicious; 40–69 = plausible; <40 = speculative. Do NOT omit this field.",
  "",
  "Return ONLY raw JSON (no markdown code fences, no prose) with EXACTLY this shape — every",
  "finding/ioc/technique/thread/event MUST be an OBJECT with these keys, never a bare string:",
  "",
  JSON.stringify(
    {
      findings: [
        {
          id: "f1",
          severity: "Critical|High|Medium|Low|Info",
          confidence: 85,
          title: "short title",
          description: "what was observed and why it matters",
          relatedIocs: ["i1"],
          mitreTechniques: ["T1059"],
          status: "open|confirmed|dismissed",
        },
      ],
      iocs: [{ id: "i1", type: "ip|domain|hash|file|process|url|other", value: "the indicator" }],
      mitreTechniques: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
      forensicEvents: [
        {
          id: "e1",
          timestamp: "2026-05-20T14:03:00Z",
          description: "powershell.exe spawned encoded command (from prefetch run time)",
          severity: "Critical|High|Medium|Low|Info",
          mitreTechniques: ["T1059.001"],
          asset: "ALCLIENT07",
        },
      ],
      threadsOpened: [{ id: "t1", description: "lead being chased" }],
      threadsClosed: ["t0"],
      timelineNote: "one sentence on what you reviewed in this batch of screenshots",
      attackerPath: "kill-chain narrative of how the attacker progressed, citing finding ids and times",
      summary: "running executive summary of the whole investigation so far",
    },
    null,
    2,
  ),
  "",
  "confidence is 0–100 (your certainty that the finding represents real attacker activity, not a false positive).",
  "If a section has nothing new, return it as an empty array (or empty string for text fields).",
].join("\n");

// Extraction prompt for an imported CSV (a Velociraptor/EDR result export). Like
// SYSTEM_PROMPT but the evidence is structured ROWS, not screenshots: each row is a
// forensic record and we want its real timestamp read from the row's own time column.
export const CSV_SYSTEM_PROMPT = [
  "You are a DFIR analyst assistant. You are given ROWS from a CSV export of forensic results",
  "(typically a Velociraptor artifact or EDR query: process listings, Windows event-log rows,",
  "netstat, prefetch, $MFT, scheduled tasks, services, shellbags, AmCache, UserAssist, etc.),",
  "plus a summary of findings already recorded.",
  "",
  "Each data row IS the evidence. For EVERY row that represents real host/attacker activity, emit a",
  "forensicEvents entry whose 'timestamp' is read FROM THAT ROW's OWN time column — pick the most",
  "relevant time field present (e.g. Mtime/Btime/Ctime/Atime, Timestamp, EventTime, Created /",
  "CreationTime, StartTime, RunTime, LastRun, FirstSeen, _ts). EMIT IT IN UTC — ISO-8601 with a",
  "trailing 'Z': convert any shown timezone offset to UTC; if the column carries no timezone, keep",
  "the wall-clock time and add 'Z' (these exports are UTC by default) — never shift a naive time.",
  "If a row has NO usable event time, set timestamp to \"\" — NEVER substitute the current time.",
  "Give each event a severity and map it to MITRE technique ids where clear.",
  "",
  "SEVERITY/LEVEL COLUMN — STRONG FINDING SIGNAL. If a row has its own Severity / Level / Criticality",
  "/ Risk column reading Critical, High, or Severe (or a high numeric score), treat it as important by",
  "default (~90% of the time it IS a finding): ALWAYS emit the forensicEvent with that severity",
  "(Severe→Critical), AND also raise a finding for it in this response. Never silently drop a",
  "Critical/High row — only skip the finding if the row is clearly benign/expected.",
  "",
  "Also surface concrete IOCs present in the rows (ips, domains, hashes, malicious file/process",
  "names, URLs). Set timelineNote to one short sentence naming the artifact and the columns you read.",
  "",
  "AFFECTED ASSET: set each event's 'asset' to the host/computer/FQDN from the row's Computer/Hostname/",
  "Fqdn/Endpoint/Device column (or the export's host); leave \"\" if none — it ties each indicator to its host.",
  "",
  "FINDINGS CONFIDENCE: every finding MUST include a 'confidence' field (integer 0–100) — your",
  "certainty that this is real attacker activity, not a false positive. Do NOT omit this field.",
  "",
  "Return ONLY raw JSON (no markdown fences). Every event/ioc MUST be an OBJECT. Shape:",
  "",
  JSON.stringify(
    {
      findings: [
        { id: "f1", severity: "Critical|High|Medium|Low|Info", confidence: 90, title: "short title (raise for any Critical/High row)", description: "what was detected and why it matters", relatedIocs: ["i1"], mitreTechniques: ["T1059"], status: "open" },
      ],
      iocs: [{ id: "i1", type: "ip|domain|hash|file|process|url|other", value: "the indicator" }],
      mitreTechniques: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
      forensicEvents: [
        { id: "e1", timestamp: "2026-05-20T14:03:00Z", description: "what happened (cite the row's key columns)", severity: "Critical|High|Medium|Low|Info", mitreTechniques: ["T1059.001"], asset: "ALCLIENT07" },
      ],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "read N rows of <artifact> (time column: <col>)",
      attackerPath: "",
      summary: "",
    },
    null,
    2,
  ),
].join("\n");

// Generic log-line extraction (firewall, syslog, sshd/auth.log, IIS/nginx/Apache
// access, Windows event-log .txt exports, application logs). Each LINE is the
// evidence — the model picks out whichever timestamp format the source uses
// (RFC 3164 syslog "May 28 09:00:01", ISO-8601, IIS "yyyy-MM-dd HH:mm:ss",
// Apache "[28/May/2026:09:00:01 +0000]", epoch seconds, etc.).
export const LOG_SYSTEM_PROMPT = [
  "You are a DFIR analyst assistant triaging a log file uploaded as evidence (typical sources:",
  "firewall logs — Cisco ASA, pfSense, iptables, Palo Alto, Fortinet; syslog; Windows event-log",
  "text exports; sshd / auth.log; Apache/IIS/nginx access logs; VPN/IKE; application logs).",
  "",
  "The raw log has already been DEDUPLICATED for you: identical recurring lines are collapsed into",
  "PATTERNS. Each pattern below shows ×<count> (how many times it occurred), the first and last time",
  "it was seen, and one example line. Treat each pattern as ONE candidate event representing all of",
  "its occurrences — do NOT emit one event per occurrence.",
  "",
  "BE SELECTIVE. A forensic timeline is for SECURITY-RELEVANT activity, not routine operations.",
  "Emit a forensicEvents entry ONLY for patterns that are suspicious, anomalous, or investigation-",
  "worthy, e.g.: authentication failures / brute force, blocked or denied traffic from unusual",
  "sources, port/host scans, IDS/IPS or AV hits, privilege changes, account or config changes,",
  "unexpected outbound connections / beaconing / data transfer, malware indicators, or an abnormal",
  "VOLUME of failures suggesting brute force or DoS.",
  "",
  "SKIP routine operational noise — do NOT emit events for it: normal VPN/IPsec rekeying, IKE",
  "keying attempts and retransmission/timeout chatter, heartbeats, successful benign connections,",
  "and informational/debug lines. A high ×count alone does NOT make a pattern suspicious; benign",
  "infrastructure noise (e.g. a tunnel repeatedly re-keying) should be skipped even at high volume.",
  "If NOTHING in this batch is security-relevant, return an empty forensicEvents array — that is the",
  "correct, expected answer for a clean/noisy operational log.",
  "",
  "For each event you DO emit, AGGREGATE the whole pattern into one entry:",
  "  - 'timestamp'    = the pattern's FIRST occurrence time, IN UTC — ISO-8601 with a trailing 'Z':",
  "                     convert a shown offset (e.g. '+0000', '+02:00') to UTC; a timezone-less syslog",
  "                     time like 'May 28 09:00:01' keeps its wall-clock and just gets a 'Z'; if there",
  "                     is no usable time set it to \"\" — NEVER use the current time,",
  "  - 'endTimestamp' = the pattern's LAST occurrence time, in UTC (omit if same as first / single event),",
  "  - 'count'        = the pattern's ×<count> occurrence number (copy it verbatim),",
  "  - 'description'  = an aggregate summary that STATES THE COUNT and time span, e.g.",
  "                     '20 failed SSH logins for root from 1.2.3.4 between 09:00:01 and 09:04:12'.",
  "Give each event a severity and map it to MITRE technique ids where clear.",
  "",
  "Also surface concrete IOCs present in the suspicious patterns (source/destination ips, domains,",
  "hashes, URLs, suspicious user/process/file names). Do NOT invent findings or an attacker path —",
  "those come from a later holistic synthesis pass. Set timelineNote to one short sentence naming",
  "the log source you inferred (e.g. 'pfSense filter log', 'sshd auth.log', 'strongSwan IKE log').",
  "",
  "Return ONLY raw JSON (no markdown fences). Every event/ioc MUST be an OBJECT. Shape:",
  "",
  JSON.stringify(
    {
      findings: [],
      iocs: [{ id: "i1", type: "ip|domain|hash|file|process|url|other", value: "the indicator" }],
      mitreTechniques: [{ id: "T1110", name: "Brute Force" }],
      forensicEvents: [
        { id: "e1", timestamp: "2026-05-20T14:03:00Z", endTimestamp: "2026-05-20T14:07:55Z", count: 20, description: "20 failed logins for 'admin' from 1.2.3.4 (possible brute force)", severity: "Critical|High|Medium|Low|Info", mitreTechniques: ["T1110.001"] },
      ],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "triaged N pattern(s) of <inferred log source>",
      attackerPath: "",
      summary: "",
    },
    null,
    2,
  ),
].join("\n");

// Holistic synthesis: turn the accumulated forensic timeline into analytic
// conclusions (findings, MITRE, attacker path). Findings/attacker-path need the
// WHOLE picture, which a single window can't see — so this runs once over the
// full timeline after per-window extraction.
export const SYNTHESIS_PROMPT = [
  "You are a senior DFIR analyst writing the CONCLUSIONS of an investigation.",
  "You are given the full forensic timeline of dated events already extracted from the evidence.",
  "Do NOT invent new events and do NOT return forensicEvents — synthesize what is given into analysis.",
  "",
  "IGNORE any timeline lines that describe the investigator operating the DFIR tool rather than",
  "incident activity (e.g. Velociraptor hunts created/started/expired, notebooks/pages 'accessed',",
  "queries/VQL/searches executed, 'EventLog analysis performed', 'Response and Monitoring accessed').",
  "Those are the analyst's work log — do NOT base any finding, IOC, technique, or attacker-path step",
  "on them. Base conclusions ONLY on real host/attacker activity (executions, logons, file/registry",
  "/network/persistence changes).",
  "",
  "Produce:",
  "- findings: produce a SEPARATE finding for EACH distinct attacker technique, tool, or behavior",
  "  observed — e.g. Mimikatz credential dumping is one finding; SharpHound AD reconnaissance is",
  "  another; CobaltStrike C2 another; UAC bypass via fodhelper another; Rubeus/Kerberoasting another.",
  "  Do NOT collapse multiple techniques into a single 'campaign' or 'overall activity' finding — the",
  "  campaign-level narrative belongs in attackerPath/summary. Aim for roughly one finding per material",
  "  technique in the timeline (often 8-20 findings for a busy case), each a CONCLUSION (not a raw log",
  "  line) with its own severity and the MITRE techniques it maps to. Also set relatedEventIds to",
  "  the ids of the forensic-timeline events (e.g. e3, e7 — shown in brackets) that this finding is",
  "  based on, so events link back to the right finding.",
  "  IMPORTANT — every [Critical] and [High] severity event in the timeline below MUST be covered by a",
  "  finding (its event id appears in some finding's relatedEventIds). A high-severity artifact row —",
  "  e.g. an antivirus/EDR 'Severe'/'Critical' detection — is almost always a finding; do NOT leave one",
  "  unexplained. Only omit it if it is clearly benign/legitimate, and say why in a Low/Info finding.",
  "  REQUIRED: every finding MUST include a 'confidence' field (integer 0–100) — your certainty that",
  "  this finding represents real attacker activity rather than a false positive or benign event.",
  "  Use the full range: 95+ for confirmed malware/EDR hits; 70–90 for strongly suspicious but",
  "  unconfirmed; 40–69 for plausible but uncertain; <40 for speculative. Do NOT omit this field.",
  "  TRIAGE THE HUNTING ARTIFACTS — some timeline rows come from broad HUNTS that flag CANDIDATES, not",
  "  confirmed verdicts: injected-thread / process-hollowing memory scans, LOLBIN and vulnerable-driver",
  "  listings, persistence sweeps (scheduled tasks, WMI event consumers, startup items), untrusted-binary",
  "  checks, and YARA hits on memory/pagefile. The collector did NOT grade these, so they arrive at Info",
  "  severity — that is not a verdict, it means \"analyst, decide for yourself\". Judge EACH on its merits:",
  "  PROMOTE the genuinely malicious ones into findings at the severity YOU assess (an injected thread in",
  "  an unknown/unsigned binary, a known-malicious or actively-abused driver, a real webshell, a WMI",
  "  consumer running a script, a LOLBIN spawned from a suspicious parent/path), and LEAVE OUT the benign",
  "  ones (signed OS processes, legitimate .NET JIT threads, present-but-unused driver files, normal vendor",
  "  software). Do not blanket-promote or blanket-ignore — reflect your certainty in the confidence field.",
  "- iocs: concrete indicators (ips, domains, hashes, malicious files/processes) seen in the timeline.",
  "- mitreTechniques: the ATT&CK techniques observed, aggregated.",
  "- attackerPath: a chronological narrative of the intrusion in kill-chain order (initial access →",
  "  execution → persistence → priv-esc → lateral movement → C2 → exfil/impact), citing event times.",
  "- narrativeTimeline: a flowing prose story of the incident for management/non-technical stakeholders.",
  "  Write chronologically in third person: 'At [time], the attacker [action]. This was followed by…'",
  "  3-5 paragraphs. Plain language — no ATT&CK T-codes, no hashes. Cite timestamps for key events.",
  "- summary: a 2-3 sentence executive overview.",
  "- threadsOpened: open an investigative thread (id + description) for each UNRESOLVED question the",
  "  evidence raises and that still needs follow-up (e.g. 'determine how the attacker obtained the",
  "  Administrator credential', 'identify the C2 domain'). Do not re-open a thread already listed below.",
  "- threadsClosed: the ids of any currently-open threads (listed below) that the evidence now RESOLVES.",
  "- keyQuestions: answer the standard DFIR questions below. For EACH, give status ('answered' |",
  "  'partial' | 'unknown'), the current best answer (or \"\" if unknown), and a 'pointer' telling the",
  "  investigator WHERE to find or confirm it — cite finding ids, event timestamps, hosts/users, or, when",
  "  unknown, the artifact to collect next (e.g. 'collect web proxy logs', 'pull $MFT on ALClient07').",
  "  Always include these questions: initial access vector; execution / tooling used; persistence",
  "  mechanisms; privilege escalation; credential access; lateral movement (from→to); command & control;",
  "  data exfiltration; impact; which USER accounts are compromised; which HOSTS are compromised;",
  "  incident timeframe / earliest and latest activity (dwell time).",
  "- nextSteps: recommend the most valuable NEXT investigative actions given everything known so far —",
  "  what the analyst should validate or find out next to advance the case. Order them by 'priority'",
  "  ('critical' | 'high' | 'medium' | 'low'), most important first. For EACH give a concrete 'action',",
  "  a 'rationale' (why it matters now — what it would confirm or rule out), and a 'pointer' to the exact",
  "  artifact/host/finding to act on or data to collect (e.g. 'pull Security.evtx 4624/4672 on ALClient07',",
  "  'sandbox-detonate Bubeus.exe', 'check web proxy logs for the C2 domain'). Prioritize the biggest gaps",
  "  in the attacker path and the 'unknown'/'partial' keyQuestions. Return 3-7 steps.",
  "",
  "Return ONLY raw JSON (no markdown fences). Set forensicEvents to [] and timelineNote to \"\".",
  "Every finding/ioc/technique/thread/question MUST be an object, never a bare string.",
  "findings must include confidence (0–100): your certainty this finding is real attacker activity, not a false positive.",
  "Shape:",
  "",
  JSON.stringify(
    {
      findings: [{ id: "f1", severity: "Critical|High|Medium|Low|Info", confidence: 85, title: "conclusion", description: "why", relatedIocs: ["i1"], mitreTechniques: ["T1562.001"], status: "open|confirmed|dismissed", relatedEventIds: ["e3", "e7"] }],
      iocs: [{ id: "i1", type: "ip|domain|hash|file|process|url|other", value: "the indicator" }],
      mitreTechniques: [{ id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools" }],
      attackerPath: "Initial access at <time> via …; then execution of …; persistence via …; impact at <time>.",
      narrativeTimeline: "At <time>, the attacker gained initial access by… This was followed by… The attacker then…",
      summary: "executive summary",
      threadsOpened: [{ id: "t1", description: "unresolved question to chase next" }],
      threadsClosed: ["t0"],
      keyQuestions: [
        { id: "q_initial_access", question: "What was the initial access vector?", status: "answered|partial|unknown", answer: "best answer or empty", pointer: "finding f3 / event 2025-04-27T10:00Z, or 'collect email gateway logs'" },
        { id: "q_lateral_movement", question: "Was there lateral movement, and from/to which hosts?", status: "partial", answer: "…", pointer: "events on ALClient07; confirm with logon 4624 on the target" },
        { id: "q_compromised_users", question: "Which user accounts are compromised?", status: "answered", answer: "…", pointer: "finding f5; Mimikatz output" },
        { id: "q_compromised_hosts", question: "Which hosts are compromised?", status: "answered", answer: "…", pointer: "…" },
      ],
      nextSteps: [
        { id: "n1", priority: "critical", action: "Pull Security.evtx (4624/4672/4688) on ALClient07 and timeline ±15m around the first execution", rationale: "Confirms the initial access vector and whether lateral movement preceded execution", pointer: "event e3 / finding f1; collect from ALClient07" },
        { id: "n2", priority: "high", action: "Sandbox-detonate Bubeus.exe and capture network IOCs", rationale: "Establishes C2 infrastructure still unknown in the timeline", pointer: "ioc i2; submit hash, watch for the C2 domain" },
      ],
      forensicEvents: [],
      timelineNote: "",
    },
    null,
    2,
  ),
].join("\n");

// --- User-overridable prompts -------------------------------------------------------
// Each of the four prompts above is the built-in DEFAULT. A user can override any of them
// from the environment (`companion/.env`), in priority order:
//   DFIR_AI_<NAME>_PROMPT       inline text (read at startup — restart to apply)
//   DFIR_AI_<NAME>_PROMPT_FILE  path to a file (re-read on each AI call — edit it and the
//                               change applies on the next analysis, no restart needed)
// <NAME> is one of: SYSTEM, CSV, LOG, SYNTH. A missing/unreadable/empty file logs a warning
// and falls back to the built-in prompt, so a typo never breaks analysis.
// `npm run prompts:eject` writes the four defaults to ./prompts as a starting point.
function resolvePrompt(name: "SYSTEM" | "CSV" | "LOG" | "SYNTH" | "ASK" | "EXEC" | "NARRATIVE" | "HUNTS" | "PBHUNTS" | "GAPHYP" | "MEMNEXT", fallback: string): string {
  const inline = process.env[`DFIR_AI_${name}_PROMPT`];
  if (inline && inline.trim().length > 0) return inline;
  const file = process.env[`DFIR_AI_${name}_PROMPT_FILE`];
  if (file && file.trim().length > 0) {
    try {
      const text = readFileSync(file, "utf8");
      if (text.trim().length > 0) return text;
      console.warn(`[DFIR] ${name} prompt file "${file}" is empty — using the built-in prompt.`);
    } catch (err) {
      console.warn(`[DFIR] could not read ${name} prompt file "${file}": ${(err as Error).message} — using the built-in prompt.`);
    }
  }
  return fallback;
}

// Answer a free-form analyst question about ONE case using only its evidence digest.
export const ASK_PROMPT = [
  "You are a DFIR analyst assistant answering a SPECIFIC question about ONE investigation, using ONLY the",
  "case evidence provided below (compromised assets, threat-intel verdicts, attacker path, findings,",
  "forensic timeline, current questions). Do NOT invent evidence — if the case doesn't show it, say so.",
  "",
  "Pick a status:",
  "- 'answered': the case evidence clearly settles it. Give the answer and cite the supporting event ids",
  "  in relatedEventIds.",
  "- 'partial': suggestive but incomplete evidence. State what is known and what is missing.",
  "- 'unknown': the case has no evidence either way.",
  "",
  "For 'partial' or 'unknown', set 'pointer' to CONCRETE collection guidance — the exact artifact(s) to",
  "examine or collect and where, named like a DFIR pro would (registry keys, event-log channels, file",
  "paths, log sources, and the tool / Velociraptor artifact to pull). Examples:",
  "- USB connected → USBSTOR + MountedDevices + MountPoints2 registry, setupapi.dev.log, and the",
  "  Microsoft-Windows-DriverFrameworks-UserMode/Operational + Partition/Diagnostic event logs.",
  "- Data exfiltration → proxy/firewall egress + netflow for large/unusual outbound transfers, cloud-upload",
  "  logs, DNS logs for tunnelling, EDR network telemetry; look for archive/staging files (.zip/.rar/.7z).",
  "- Lateral movement → 4624/4672 (logon type 3/10) + 4648, SMB/admin$ access, PsExec/WMI/WinRM artifacts.",
  "Tailor it to the question and keep 'answer' to a few sentences.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({
    answer: "concise answer grounded in the evidence (or what's missing)",
    status: "answered|partial|unknown",
    pointer: "which artifact to examine/collect and where (required for partial/unknown)",
    relatedEventIds: ["e1"],
  }, null, 2),
].join("\n");

// Write a management-facing executive summary of ONE case from its synthesized digest. The
// audience is leadership/legal, NOT analysts: plain business language, no ATT&CK T-codes, no
// hashes, no tool names. Grounded only in the provided evidence — no invented impact.
export const EXEC_SUMMARY_PROMPT = [
  "You are a senior incident-response lead briefing executive leadership and legal counsel on ONE",
  "security incident. Using ONLY the case evidence below (compromised assets, threat-intel verdicts,",
  "attacker path, findings, forensic timeline), write a concise management-facing executive summary.",
  "",
  "Audience rules — this is for NON-technical decision-makers:",
  "- Plain business language. NO ATT&CK technique ids, NO hashes, NO tool/product names, NO event ids.",
  "- Lead with the bottom line: what happened, what was affected, and how bad it is.",
  "- Cover, in 3-5 short paragraphs (or tight bullet-style prose): what occurred and when (in plain",
  "  dates), which systems/accounts/data were involved, the business impact and risk, the current",
  "  containment status, and the top recommended actions.",
  "- Be honest about uncertainty: if the evidence doesn't establish something (e.g. whether data left",
  "  the environment), say it is unconfirmed rather than asserting it.",
  "- Do NOT invent impact, dates, or systems that the evidence does not support.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({ summary: "the executive summary as a few plain-language paragraphs (use \\n\\n between them)" }, null, 2),
].join("\n");

// Standalone narrative-timeline generator: produces a stakeholder-friendly prose story of the
// incident. Used by `generateNarrative()` when the analyst clicks "Generate" without re-running
// full synthesis. The same narrative is also generated as part of synthesis via SYNTHESIS_PROMPT.
export const NARRATIVE_PROMPT = [
  "You are a senior incident-response analyst writing a narrative timeline for ONE security incident.",
  "Using ONLY the case evidence provided (attacker path, findings, forensic timeline), write a flowing",
  "chronological prose story of the incident for management and non-technical stakeholders.",
  "",
  "Audience: decision-makers who need to understand WHAT HAPPENED and WHEN, not technical details.",
  "Format:",
  "- Flowing prose paragraphs — NOT bullet points.",
  "- Chronological order, citing specific timestamps for key events.",
  "- Third person: 'the attacker', 'the threat actor', 'the adversary'.",
  "- Template: 'At [time], the attacker [action]. This was followed by [next step] at [time]...'",
  "- Plain language: no ATT&CK T-codes, no hashes, no jargon. Explain tools in plain terms.",
  "- Be honest about uncertainty: if timing or method is unclear, say 'approximately' or 'at some point'.",
  "- 3-6 paragraphs. Each paragraph covers one phase of the intrusion.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({ narrativeTimeline: "the flowing story as prose paragraphs (use \\n\\n between paragraphs)" }, null, 2),
].join("\n");

// Propose PROACTIVE Velociraptor VQL fleet-hunts from the synthesized findings (issue #57). The
// model reads the findings / ATT&CK techniques / pivotable IOCs and emits hunts that run on EVERY
// enrolled endpoint to find the same tradecraft elsewhere. The VQL must be deployable as-is via the
// CLIENT-artifact hunt path (launchHunt), so the shape constraints here mirror what splitVqlStatements
// expects: ONE self-contained VQL statement per hunt, no blank-line splits, not comment-only.
export const HUNT_SUGGEST_PROMPT = [
  "You are a senior DFIR threat hunter. Given ONE investigation's findings, ATT&CK techniques,",
  "compromised assets, and indicators below, propose PROACTIVE Velociraptor VQL HUNTS that run",
  "across the ENTIRE fleet of enrolled endpoints to find the SAME adversary tradecraft on hosts",
  "that are not yet in scope — lateral spread, the same webshell/persistence/malware pattern,",
  "the same C2, the same living-off-the-land technique.",
  "",
  "Rules:",
  "- Hunt for the PATTERN across the fleet, do NOT merely restate a single-host finding. If a",
  "  webshell was found in one web root, hunt every host's web roots; if a malicious service was",
  "  installed, enumerate that service/registry value everywhere.",
  "- Pivot ONLY on the case's REAL indicators (the exact hashes, file paths, process names,",
  "  service names, domains, IPs shown below). Do NOT invent IOCs the case does not contain.",
  "- Each `vql` MUST be a SINGLE, self-contained, CLIENT-side Velociraptor VQL statement that runs",
  "  on each endpoint — one `SELECT … FROM <plugin>(…) WHERE …`. Use real Velociraptor plugins,",
  "  e.g. glob(), stat(), pslist(), Artifact.Windows.System.Services, Artifact.Windows.Sys.Users,",
  "  read_file(), hash(), yara(), Artifact.Windows.Registry.* . Velociraptor glob() uses FORWARD",
  "  slashes. Do NOT put a blank line inside one query and do NOT make a query only a comment.",
  "- Use each plugin's REAL argument names. parse_evtx() takes `filename=` (a path or glob), NOT",
  "  `files=` — e.g. parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx'). For Windows",
  "  event-log hunts PREFER Velociraptor's own artifacts (Windows.EventLogs.* / Windows.Detection.*)",
  "  over hand-writing parse_evtx, and access fields as `System.EventID.Value` / `EventData.<Name>`.",
  "- read_file() takes `filenames=` (a LIST), NOT `filename=` (scalar). To read one file:",
  "  `SELECT Data FROM read_file(filenames=['C:/path/file.txt'])`. To read files found by glob,",
  "  call it inline in the SELECT (no JOIN needed):",
  "  `SELECT FullPath, read_file(filenames=[FullPath])[0].Data AS Content FROM glob(globs='...')`.",
  "- VQL has NO SQL `JOIN`. Use inline function calls (e.g. read_file above) or",
  "  `foreach(row={SELECT … FROM a()}, query={SELECT … FROM b()})` to correlate two plugins.",
  "- PREFER raw VQL plugins — pslist(), netstat(), glob(), stat(), read_file(), hash(), yara() — over",
  "  `Artifact.<Name>()` references: a hallucinated Artifact.<Name> fails to COMPILE and the hunt never",
  "  starts. Network connections → netstat(); processes → pslist(); files → glob(). Only reference an",
  "  Artifact.<Name> you are sure exists on the server.",
  "- For an ABSOLUTE time use timestamp(string='2025-03-14T22:00:00Z'); epoch= takes unix SECONDS (a number).",
  "- Velociraptor VQL has NO duration-suffix literals. Do NOT write `30d`, `7h`, `2w` etc.",
  "  Use seconds arithmetic instead: `now() - 30 * 86400` (30 days), `now() - 7 * 86400` (7 days),",
  "  `now() - 3600` (1 hour). Wrap in `timestamp(epoch=...)` when comparing against a timestamp",
  "  column, e.g. `WHERE Mtime > timestamp(epoch=now() - 30 * 86400)`.",
  "- Prefer a few HIGH-SIGNAL hunts over many near-duplicates. Skip a finding if there is nothing",
  "  fleet-wide to hunt for it.",
  "- For each hunt set: a short `title`; a `rationale` (which finding triggered it, what the query",
  "  looks for, and how to triage a hit); `severity` (Critical|High|Medium|Low|Info) of the",
  "  underlying threat; `mitreTechniques` (the finding's technique ids); and `relatedFindingIds`",
  "  (the finding ids it derives from, using the [ids] shown).",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({
    suggestions: [{
      title: "Hunt for ASPX webshells across IIS web roots",
      rationale: "Finding f3 shows an ASPX webshell on WEB01. Sweep every endpoint's web roots for .aspx files written recently; triage any hit by author/last-write time and contents.",
      vql: "SELECT FullPath, Mtime, Size FROM glob(globs='C:/inetpub/wwwroot/**/*.aspx') WHERE Mtime > timestamp(epoch=now() - 2592000)",
      severity: "High",
      mitreTechniques: ["T1505.003"],
      relatedFindingIds: ["f3"],
    }],
  }, null, 2),
].join("\n");

// Issue #70 — AI-suggested Velociraptor hunts for the case's PLAYBOOK tasks. For each ENDPOINT-related
// task the model writes one CLIENT-side VQL hunt + echoes the single host it's scoped to (chosen ONLY
// from the provided known-endpoints list). The server decides hunt-vs-collection deterministically
// from the observed endpoints, so the model just needs to flag endpoint-relatedness and name the host.
export const PLAYBOOK_HUNT_PROMPT = [
  "You are a senior DFIR threat hunter. Below is ONE investigation's Response PLAYBOOK (the analyst's",
  "actionable checklist), the case's known ENDPOINTS, findings, ATT&CK techniques, and forensic timeline.",
  "For each playbook task that is ABOUT ENDPOINTS (collecting from, examining, containing, or hunting on",
  "hosts — e.g. pull event logs, enumerate persistence, find a process/file, scope lateral movement),",
  "propose ONE Velociraptor VQL hunt that gathers the evidence the task needs.",
  "",
  "Rules:",
  "- Only emit a suggestion for a task that is genuinely endpoint-related. Set `endpointRelated` true for",
  "  those and SKIP the rest (notify legal, rotate cloud creds, draft a report, block a domain at the",
  "  firewall, etc. are NOT endpoint tasks). It is fine to return fewer suggestions than tasks.",
  "- `taskId` MUST be the exact id (the [bracketed] value) of the task the suggestion is for.",
  "- `targetHost`: if the task is about exactly ONE specific endpoint, set this to that host — but ONLY a",
  "  hostname that appears in the KNOWN ENDPOINTS list below (the server runs it as a COLLECTION on just",
  "  that one client). If the task spans multiple hosts, or you are unsure which host, set `targetHost`",
  "  to \"\" (the server runs it as a fleet-wide HUNT across all endpoints). Never invent a hostname.",
  "- Each `vql` MUST be a SINGLE, self-contained, CLIENT-side Velociraptor VQL statement —",
  "  one `SELECT … FROM <plugin>(…) WHERE …`. glob() uses FORWARD slashes. Do NOT put a blank line",
  "  inside one query and do NOT make a query only a comment.",
  "- STRONGLY PREFER raw VQL plugins — they ALWAYS exist: pslist(), netstat(), glob(), stat(),",
  "  read_file(), hash(), yara(), parse_evtx(), reg_keys(). Network connections → netstat(); processes →",
  "  pslist(); files → glob(); event logs → parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx').",
  "- You MAY reference an `Artifact.<Name>()` ONLY if <Name> appears EXACTLY in the AVAILABLE VELOCIRAPTOR",
  "  ARTIFACTS list in the user message below. If <Name> is NOT in that list it does NOT exist on this",
  "  server and the hunt FAILS TO COMPILE (no flow id) — use a raw plugin instead. NEVER invent an",
  "  artifact name (e.g. Windows.EventLogs.Sysmon / .SecurityLog are NOT universal — check the list).",
  "- Use each plugin's REAL argument names: parse_evtx() takes `filename=` (a path/glob), NOT `files=`;",
  "  handles() takes `pid=`, NOT `process=`; read_file() takes `filenames=` (a LIST), NOT `filename=`.",
  "  Access EVTX fields as `System.EventID.Value` / `EventData.<Name>`. To read one file:",
  "  `SELECT Data FROM read_file(filenames=['C:/path/file.txt'])`. To read files found by glob,",
  "  call it inline in the SELECT (no JOIN needed):",
  "  `SELECT FullPath, read_file(filenames=[FullPath])[0].Data AS Content FROM glob(globs='...')`.",
  "- VQL has NO SQL `JOIN`. Use inline function calls (e.g. read_file above) or",
  "  `foreach(row={SELECT … FROM a()}, query={SELECT … FROM b()})` to correlate two plugins.",
  "- For an ABSOLUTE time use timestamp(string='2025-03-14T22:00:00Z'); epoch= takes unix SECONDS (a number).",
  "- Velociraptor VQL has NO duration-suffix literals. Do NOT write `30d`, `7h`, `2w`. Use seconds",
  "  arithmetic: `now() - 30 * 86400` (30 days), `now() - 3600` (1 hour). Wrap in `timestamp(epoch=...)`",
  "  when comparing a timestamp column, e.g. `WHERE Mtime > timestamp(epoch=now() - 30 * 86400)`.",
  "- Pivot on the case's REAL indicators (the exact hashes, file paths, process/service names, domains,",
  "  IPs shown) — do NOT invent IOCs the case does not contain.",
  "- For each: a short `title`; a `rationale` (which task it serves, what the query looks for, how to",
  "  triage a hit); `severity` (Critical|High|Medium|Low|Info) of the underlying threat; and",
  "  `mitreTechniques` (relevant technique ids).",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({
    suggestions: [{
      taskId: "finding:f3",
      endpointRelated: true,
      title: "Enumerate the malicious service on WEB01",
      rationale: "Task asks to investigate the service-persistence finding on WEB01. Collect the host's services and flag the one whose ImagePath matches the dropped binary; triage by start type and account.",
      vql: "SELECT Name, DisplayName, PathName, StartMode FROM Artifact.Windows.System.Services() WHERE PathName =~ 'evil\\\\.exe'",
      targetHost: "WEB01",
      severity: "High",
      mitreTechniques: ["T1543.003"],
    }],
  }, null, 2),
].join("\n");

// Hypothesise attacker actions for TIMELINE GAPS (issue #96). The deterministic gap detector has
// already flagged suspiciously silent periods; the model reads each gap's bounding context — the
// events just BEFORE the silence and just AFTER — and infers what the attacker most likely did during
// the hole (e.g. cleared the log to hide credential dumping, disabled EDR before lateral movement).
// It is grounded ONLY in the surrounding events; it does NOT invent activity. It also names which
// SHADOW ARTIFACTS (from the catalog ids in the user message) would best reconstruct each window —
// the deterministic catalog supplies the actual collection VQL, so the model only ranks relevance.
export const GAP_HYPOTHESIS_PROMPT = [
  "You are a senior DFIR analyst reasoning about COVERAGE GAPS in ONE investigation's forensic timeline.",
  "Each gap below is a stretch where logging went silent — a COMPLETE gap (every source dark) is the",
  "classic signature of cleared Windows Event Logs, a stopped collector/auditd, or disabled EDR. For",
  "EACH gap, hypothesise what the attacker most likely did DURING the silence, reasoning from the events",
  "immediately BEFORE the gap (what they were doing) and immediately AFTER (the state when logging",
  "resumed).",
  "",
  "Rules:",
  "- Ground every hypothesis ONLY in the surrounding events shown. Do NOT invent specific hosts, files,",
  "  or accounts the context does not mention. If the surrounding events are too sparse to say anything,",
  "  give a low confidence and say the gap is unexplained.",
  "- Prefer the explanation that fits the tradecraft: a complete silence right after initial access often",
  "  hides discovery/credential-access/defense-evasion (clearing logs to cover the next step); a gap",
  "  bracketed by a logon and later persistence often hides lateral movement or staging.",
  "- `gapId` MUST be the exact [gap-N] id shown for the gap the hypothesis is about. Emit at most one",
  "  hypothesis per gap. It is fine to skip a gap that is plainly benign (e.g. an expected overnight quiet).",
  "- `hypothesis`: 2-4 sentences naming the most probable attacker activity and WHY it fits the context.",
  "- `attackerActions`: a few concrete candidate actions that would produce this exact gap.",
  "- `confidence`: 0-100, honest — sparse context or an equally-likely benign explanation means LOW.",
  "- `severity`: Critical|High|Medium|Low|Info — how serious the hypothesised activity would be.",
  "- `mitreTechniques`: ATT&CK ids for the hypothesised actions (e.g. T1070.001 for cleared event logs).",
  "- `recommendedArtifactIds`: from the SHADOW ARTIFACTS list in the user message, the ids whose data",
  "  would best confirm THIS hypothesis (e.g. prefetch/amcache/shimcache/bam for execution, usn-journal/",
  "  mft/lnk-files for file activity, srum for exfiltration). Use ONLY ids from that list.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({
    hypotheses: [{
      gapId: "gap-1",
      hypothesis: "The Security log was cleared immediately after the initial RDP logon and before the service-install seen on resume, consistent with the attacker wiping logs to hide credential access and staging during the silence.",
      attackerActions: ["Cleared the Windows Security event log (wevtutil cl / EventLog API)", "Dumped LSASS or ran a discovery tool while logging was off"],
      confidence: 55,
      severity: "High",
      mitreTechniques: ["T1070.001", "T1003.001"],
      recommendedArtifactIds: ["prefetch", "amcache", "usn-journal", "srum"],
    }],
  }, null, 2),
].join("\n");

// Memory-forensics "Next-Step" agent (issue #101). The case already has Volatility 3 / Rekall output
// imported as forensic events (the process tree, network connections, malfind injected code, command
// lines, services, modules). Read that memory evidence, identify the ANOMALIES, and propose the EXACT
// next Volatility 3 command the analyst should run to dig deeper. The agent CONSUMES the enumeration
// (it does not re-implement Volatility) — it reasons over the rows and recommends the next plugin.
export const MEMORY_NEXTSTEP_PROMPT = [
  "You are a senior memory-forensics analyst guiding an ITERATIVE Volatility 3 investigation. Below is",
  "the memory evidence ALREADY imported from a RAM image (Volatility 3 / Rekall output): the process",
  "tree (process name, PID, PPID, parent name, start time, command line), network connections, malfind",
  "(executable/injected private memory), command lines, services, and loaded modules. Identify the",
  "ANOMALIES and, for each, propose the EXACT next Volatility 3 command the analyst should run to dig in.",
  "",
  "What counts as an anomaly (reason from the evidence shown, do NOT invent processes/PIDs):",
  "- Process-tree masquerading / wrong parentage: svchost.exe NOT parented by services.exe; lsass.exe,",
  "  csrss.exe, services.exe, wininit.exe with the wrong/absent parent; an unparented process; a system",
  "  binary running from a non-system path; a user app spawning cmd.exe/powershell.exe.",
  "- Injected/executable private memory (malfind hits) → dump and scan the region.",
  "- Suspicious or external network connections owned by an unexpected process (possible C2/beacon).",
  "- LOLBin / encoded-PowerShell / unusual command lines.",
  "- A persistence-looking service or an unsigned/odd module.",
  "",
  "Rules:",
  "- Each `command` MUST be a single, real, copy-pasteable Volatility 3 command. Use `vol -f <image>`",
  "  as the prefix (the analyst substitutes their image path for <image>) followed by a REAL Volatility 3",
  "  plugin and its REAL options, e.g.:",
  "    vol -f <image> windows.malfind --pid 1234",
  "    vol -f <image> windows.dlllist --pid 1234",
  "    vol -f <image> windows.cmdline --pid 1234",
  "    vol -f <image> windows.handles --pid 1234",
  "    vol -f <image> windows.netscan",
  "    vol -f <image> windows.pstree",
  "    vol -f <image> windows.dumpfiles --pid 1234",
  "    vol -f <image> windows.svcscan",
  "  Use Linux/Mac plugin names (linux.* / mac.*) instead if the evidence is clearly from that OS.",
  "  Use the REAL plugin/option names — do NOT invent plugins or flags, and do NOT use Volatility 2",
  "  syntax (no `--profile`, no `vol.py -f mem.raw pslist`-style v2 plugin names).",
  "- PREFER suggesting plugins that have NOT been run yet (the user message lists the already-imported",
  "  plugins) when they would advance the investigation — the point is the NEXT step, not re-running",
  "  what is already on the timeline. Pivot on a SPECIFIC PID/process from the evidence wherever the",
  "  plugin takes `--pid`; set `pid` to that PID.",
  "- Prefer a few HIGH-SIGNAL next steps over many near-duplicates. If nothing in the evidence looks",
  "  anomalous, it is fine to return fewer (or no) suggestions.",
  "- For each: a short `anomaly` (the observation that triggered it, naming the real process/PID); the",
  "  `command`; the `plugin` it runs (e.g. windows.malfind); a `rationale` (why run it + how to triage",
  "  what it returns); `severity` (Critical|High|Medium|Low|Info) of the underlying anomaly;",
  "  `pid` (the targeted PID, or \"\"); and `mitreTechniques` (relevant ATT&CK ids, e.g. T1055 for injection).",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape:",
  JSON.stringify({
    suggestions: [{
      anomaly: "svchost.exe (PID 1234) is parented by explorer.exe (PID 4500), not services.exe — classic masquerading.",
      command: "vol -f <image> windows.malfind --pid 1234",
      plugin: "windows.malfind",
      rationale: "A mis-parented svchost is a strong injection/masquerade signal. malfind dumps executable private memory in the process; triage any MZ/shellcode region by yara-scanning the dump and pivot on its imports.",
      severity: "High",
      pid: "1234",
      mitreTechniques: ["T1055", "T1036.005"],
    }],
  }, null, 2),
].join("\n");

export const getSystemPrompt = (): string => resolvePrompt("SYSTEM", SYSTEM_PROMPT);
export const getCsvPrompt = (): string => resolvePrompt("CSV", CSV_SYSTEM_PROMPT);
export const getLogPrompt = (): string => resolvePrompt("LOG", LOG_SYSTEM_PROMPT);
export const getSynthesisPrompt = (): string => resolvePrompt("SYNTH", SYNTHESIS_PROMPT);
export const getAskPrompt = (): string => resolvePrompt("ASK", ASK_PROMPT);
export const getExecSummaryPrompt = (): string => resolvePrompt("EXEC", EXEC_SUMMARY_PROMPT);
export const getNarrativePrompt = (): string => resolvePrompt("NARRATIVE", NARRATIVE_PROMPT);
export const getHuntSuggestPrompt = (): string => resolvePrompt("HUNTS", HUNT_SUGGEST_PROMPT);
export const getPlaybookHuntPrompt = (): string => resolvePrompt("PBHUNTS", PLAYBOOK_HUNT_PROMPT);
export const getGapHypothesisPrompt = (): string => resolvePrompt("GAPHYP", GAP_HYPOTHESIS_PROMPT);
export const getMemoryNextStepPrompt = (): string => resolvePrompt("MEMNEXT", MEMORY_NEXTSTEP_PROMPT);

export interface PipelineOptions {
  provider?: AIProvider;
  // Optional stronger model for the holistic synthesis pass. Per-window extraction
  // can use a cheap model while synthesis (one text-only call) uses a better one.
  synthesisProvider?: AIProvider;
  // Optional DEDICATED model for Velociraptor VQL hunt generation (#70) — many models botch VQL,
  // so the analyst can pin a known-good one just for suggestHunts/suggestPlaybookHunts. Falls back
  // to synthesisProvider, then the main provider.
  velociraptorProvider?: AIProvider;
  // Client-confirmed legitimate findings/IOCs to exclude from synthesis.
  legitimateStore?: LegitimateStore;
  // Optional investigation time-window — events outside it are excluded.
  scopeStore?: ScopeStore;
  // Per-case anonymization control. When a case has it enabled, the userPrompt is tokenized
  // before the provider call and the response is restored before parsing. Optional: absent →
  // no anonymization (used by older tests).
  anonStore?: AnonControlStore;
  // Per-case analyst-added entities to anonymize (exact-match), merged with the auto-derived ones.
  customEntitiesStore?: CustomEntitiesStore;
  // Per-case OCR-discovered entities + the analyst's suppression list. When set, the OCR pass feeds
  // every entity it tokenizes out of a screenshot back here (so the auto-discovery list grows), and
  // suppressed values are excluded from anonymization. Absent → no screenshot auto-discovery.
  discoveredStore?: DiscoveredEntitiesStore;
  stateStore: StateStore;
  imageLoader: (caseId: string, screenshotFile: string) => Promise<AnalyzeImage>;
  retries?: number;
  backoffMs?: number;
  onState?: (state: InvestigationState) => void;
  // Optional: fired after a REAL synthesis run (not a skip) with the findings diff + the new state,
  // so the server can dispatch notifications (issue #58 — new/escalated findings). Best-effort; the
  // pipeline never awaits it. Absent → no notifications (used by CLI scripts/tests).
  onSynth?: (caseId: string, diff: FindingsDiff, state: InvestigationState) => void;
  // Optional: record when synthesis actually ran + what changed in the findings, so the
  // dashboard can show "last synthesized N ago" and a what-changed diff. Absent → not recorded.
  synthMetaStore?: SynthMetaStore;
  // When both notebookStore and aiControlStore are set, synthesis checks aiControl.includeNotebook
  // and — when true — appends the analyst's notebook entries to the synthesis prompt.
  notebookStore?: NotebookStore;
  aiControlStore?: AiControlStore;
  // When set (external AI provider only), each screenshot is OCR-redacted before the vision
  // call: words the anonymizer would tokenize are covered with opaque rectangles. The original
  // evidence file is never touched — only the in-memory buffer sent to the model is redacted.
  ocrRunner?: OcrRunner;
  // Shared leveled logger. Absent → a console-only logger at DFIR_LOG_LEVEL (used by CLI scripts
  // and tests). The server passes its file-backed logger so AI/OCR/anon traces land in the case log.
  logger?: Logger;
  // CISA KEV catalog (issue #99): when set, CVEs found in forensic events + IOCs are matched
  // against the catalog and the hits are prepended to the synthesis context so the AI can flag
  // actively-exploited CVEs as probable initial-access vectors. Opt-in (store starts empty).
  kevStore?: KevStore;
}

// Keep analyst-pinned questions across a synthesis. The model is told about them and may
// answer one (same id) — keep that, flagged pinned; if it dropped one, re-add the original.
function mergePinnedQuestions(pinned: InvestigationQuestion[], current: InvestigationQuestion[]): InvestigationQuestion[] {
  if (pinned.length === 0) return current;
  const byId = new Map(current.map((q) => [q.id, q]));
  for (const p of pinned) {
    const cur = byId.get(p.id);
    byId.set(p.id, cur ? { ...cur, pinned: true } : p);
  }
  return [...byId.values()];
}

async function withRetry<T>(fn: () => Promise<T>, retries: number, backoffMs: number): Promise<T> {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= retries) throw err;
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
      attempt++;
    }
  }
}

export class AnalysisPipeline {
  private readonly log: Logger;
  // Lazily loaded from opts.kevStore so we don't block the constructor on disk I/O.
  private kevCatalogCache: KevCatalog | undefined;

  constructor(private readonly opts: PipelineOptions) {
    this.log = opts.logger ?? createConsoleLogger(normalizeLogLevel(process.env.DFIR_LOG_LEVEL));
  }

  private async getKevCatalog(): Promise<KevCatalog | undefined> {
    if (!this.opts.kevStore) return undefined;
    if (!this.kevCatalogCache) this.kevCatalogCache = await this.opts.kevStore.loadCatalog();
    return this.kevCatalogCache;
  }

  // Called by the /kev routes after a catalog update so the next synthesis picks it up.
  invalidateKevCache(): void {
    this.kevCatalogCache = undefined;
  }

  hasAiProvider(): boolean {
    return Boolean(this.opts.provider);
  }

  private requireProvider(purpose: string): AIProvider {
    if (!this.opts.provider) throw new Error(`AI provider not configured; ${purpose} requires an AI provider`);
    return this.opts.provider;
  }

  // Run one AI call with optional per-case anonymization. Tokenizes the userPrompt and —
  // when an ocrRunner is configured (external provider only) — OCR-redacts image buffers
  // before sending. The original image files on disk are never touched; only the in-memory
  // copies forwarded to the model are redacted. Restores the parsed JSON response BEFORE
  // schema validation so real values with JSON metacharacters never corrupt parsing.
  private async analyzeRestored(
    caseId: string,
    state: InvestigationState,
    provider: AIProvider,
    req: AnalyzeRequest,
    label = "ai",
  ): Promise<unknown> {
    const control = this.opts.anonStore ? await this.opts.anonStore.load(caseId) : null;
    const policy = toAnonPolicy(control);
    this.log.debug(
      `AI call [${label}] provider=${provider.name} images=${req.images.length} ` +
        `promptChars=${req.userPrompt.length} anonymize=${policy.enabled ? "on" : "off"}`,
      { caseId },
    );
    if (!policy.enabled) {
      const result = await provider.analyze(req);
      this.logAiUsage(caseId, label, provider, result);
      return parseJsonLoose(result.rawText);
    }
    const known = deriveKnownEntities(state);
    const custom = this.opts.customEntitiesStore ? await this.opts.customEntitiesStore.load(caseId) : [];
    // Auto-discovered screenshot entities are tokenized too; suppressed ones are never tokenized.
    const disc = this.opts.discoveredStore ? await this.opts.discoveredStore.load(caseId) : { discovered: [], suppressed: [] };
    known.custom = [...custom, ...disc.discovered];
    known.suppressed = disc.suppressed;
    const anon = createAnonymizer(policy, known);
    this.log.debug(`anonymized prompt before [${label}] AI call`, { caseId });

    // OCR-discovered entities to persist into the case's auto-discovery list after this pass.
    const discoveredFromOcr: CustomEntity[] = [];

    // OCR-redact image buffers when an external-provider runner is configured.
    let images = req.images;
    if (this.opts.ocrRunner && images.length > 0) {
      const runner = this.opts.ocrRunner;
      // DFIR_OCR_DEBUG forces the per-image detail to INFO (always shown); otherwise it is a
      // DEBUG line, surfaced when DFIR_LOG_LEVEL=debug or the dashboard's Logging toggle is on.
      const forceInfo = !!process.env.DFIR_OCR_DEBUG;
      const dumpDir = process.env.DFIR_OCR_DEBUG_DIR;      // write the redacted copy for inspection
      const count = images.length;
      let totalRedactions = 0;
      let redactedImages = 0;
      images = await Promise.all(
        images.map(async (img, i) => {
          try {
            const buf = Buffer.from(img.base64, "base64");
            const res = await ocrRedactImage(buf, policy, known, runner);
            if (res.discovered.length) discoveredFromOcr.push(...res.discovered);
            if (res.changed) {
              redactedImages++;
              totalRedactions += res.redactions.length;
              if (dumpDir) await dumpRedactedImage(dumpDir, caseId, i, img.mimeType, res.buffer);
            }
            const matched = res.redactions.map((w) => w.text).join(", ");
            const line =
              `[OCR] image ${i + 1}/${count}: read ${res.wordCount} word(s), ` +
              `redacted ${res.redactions.length}${matched ? ` [${matched}]` : ""}`;
            if (forceInfo) this.log.info(line, { caseId });
            else this.log.debug(line, { caseId });
            return res.changed ? { ...img, base64: res.buffer.toString("base64") } : img;
          } catch (err) {
            // OCR failure is non-fatal — log and forward the original image.
            this.log.warn(`[OCR redact] ${(err as Error).message}`, { caseId });
            return img;
          }
        }),
      );
      // Always-on confirmation that the OCR pre-pass ran (vs. images going to the model
      // unredacted because anon is off or the provider is local). One line per analyze call.
      this.log.info(
        `[OCR] redaction ran on ${count} screenshot(s) — scrubbed ` +
          `${totalRedactions} word(s) across ${redactedImages} image(s) before sending to the model`,
        { caseId },
      );
      // Feed what OCR tokenized back into the case's auto-discovery list (dedupe/suppress handled
      // by the store). Best-effort — a write failure must not fail the analysis.
      if (this.opts.discoveredStore && discoveredFromOcr.length > 0) {
        try {
          const added = await this.opts.discoveredStore.addDiscovered(caseId, discoveredFromOcr);
          this.log.debug(`[OCR] auto-discovery now holds ${added.discovered.length} entit(y/ies)`, { caseId });
        } catch (err) {
          this.log.warn(`[OCR] could not persist discovered entities: ${(err as Error).message}`, { caseId });
        }
      }
    }

    const result = await provider.analyze({ ...req, userPrompt: anon.apply(req.userPrompt), images });
    this.logAiUsage(caseId, label, provider, result);
    return anon.restoreDeep(parseJsonLoose(result.rawText));
  }

  // Log token usage at DEBUG after a provider call (surfaced with DFIR_LOG_LEVEL=debug).
  private logAiUsage(caseId: string, label: string, provider: AIProvider, result: AnalyzeResult): void {
    const u = result.usage;
    if (!u) {
      this.log.debug(`AI call [${label}] done provider=${provider.name} (no usage reported)`, { caseId });
      return;
    }
    const cache =
      (u.cacheReadTokens ? ` cacheRead=${u.cacheReadTokens}` : "") +
      (u.cacheCreationTokens ? ` cacheWrite=${u.cacheCreationTokens}` : "");
    this.log.debug(
      `AI call [${label}] done provider=${provider.name} in=${u.inputTokens ?? "?"} out=${u.outputTokens ?? "?"}${cache}`,
      { caseId },
    );
  }

  // Hash of the last successfully-synthesized inputs per case. The live, debounced
  // synthesis fires after every capture window; this lets us skip the (expensive) AI call
  // when nothing that affects the output has changed since the last run. In-memory: a
  // fresh process (or an explicit `force`) always synthesizes.
  private readonly lastSynthHash = new Map<string, string>();

  async analyzeWindow(caseId: string, captures: CaptureMetadata[]): Promise<InvestigationState> {
    const provider = this.requireProvider("screenshot analysis");
    const analyzable = captures.filter((c) => !c.isDuplicate);
    if (analyzable.length === 0) return this.opts.stateStore.load(caseId);

    const state = await this.opts.stateStore.load(caseId);
    const images = await Promise.all(
      analyzable.map((c) => this.opts.imageLoader(caseId, c.screenshotFile)),
    );
    // Note: we deliberately do NOT put the capture time on these lines — the model
    // would otherwise copy it into forensicEvents instead of reading the artifact's
    // own timestamp column shown in the image.
    const contextLines = analyzable
      .map((c) => `Screenshot ${c.screenshotFile} — ${c.tabTitle} (${c.url})`)
      .join("\n");
    const userPrompt =
      `${buildStateSummary(state)}\n\nNEW SCREENSHOTS (read each artifact's OWN timestamp column ` +
      `for event times — do not use any capture/current time):\n${contextLines}\n\nReturn the JSON delta.`;

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;

    const delta = await withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, state, provider, { systemPrompt: getSystemPrompt(), userPrompt, images }, "extract");
      return deltaSchema.parse(parsed);
    }, retries, backoffMs);

    const windowSequence = analyzable[analyzable.length - 1].sequenceNumber;
    // Tag each event's source for correlation/corroboration: detect the real tool from the
    // captured tab titles (e.g. "Velociraptor", "CrowdStrike Falcon"), else generic "screenshot".
    const winSource = detectTool(analyzable.map((c) => c.tabTitle).join(" ")) ?? "screenshot";
    const tagged = { ...delta, forensicEvents: (delta.forensicEvents ?? []).map((e) => ({ ...e, sources: e.sources?.length ? e.sources : [winSource] })) };
    const next = mergeDelta(state, tagged, {
      windowSequence,
      timestamp: analyzable[analyzable.length - 1].timestamp,
      sourceScreenshots: analyzable.map((c) => c.screenshotFile),
    });
    await this.opts.stateStore.save(next);
    this.opts.onState?.(next);
    return next;
  }

  // Import an uploaded CSV (e.g. a Velociraptor result export) as evidence: extract
  // dated forensic events + IOCs from the rows, batch by batch, into the timeline —
  // the same delta the screenshot path produces. Findings/TTPs/attacker-path come
  // afterwards from synthesize() (call it after this resolves), exactly like capture.
  async analyzeCsv(
    caseId: string,
    csvText: string,
    opts: {
      label: string;             // evidence label shown as the event source (stored filename)
      idPrefix: string;          // unique per import (e.g. "m3") so event ids never collide
      importedAt: string;        // ISO time used for timeline/firstSeen context
      rowsPerBatch?: number;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const provider = this.requireProvider("CSV analysis");
    const { headers, rows } = parseCsv(csvText);
    if (rows.length === 0) return this.opts.stateStore.load(caseId);

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;

    let state = await this.opts.stateStore.load(caseId);
    let evSeq = 0; // running counter → globally unique forensic-event ids for this import

    // Batch by BOTH the row cap and a token budget: wide rows (long EDR/SIEM command-lines)
    // could otherwise pack 50 rows into a prompt that overflows the model context. Reserve
    // room for the system prompt + the state-summary that's prepended to every batch.
    const csvOverhead = estimateTokens(getCsvPrompt()) + estimateTokens(buildStateSummary(state))
      + estimateTokens(chunkToCsvText(headers, [])) + 64;
    const rowBudget = Math.max(0, inputTokenBudget() - csvOverhead);
    const batches = batchByBudget(rows, opts.rowsPerBatch ?? 50, (r) => r.join(","), rowBudget);

    for (let b = 0; b < batches.length; b++) {
      const csvChunk = chunkToCsvText(headers, batches[b]);
      const userPrompt =
        `${buildStateSummary(state)}\n\nCSV ARTIFACT ROWS (source: ${opts.label}; batch ${b + 1}/${batches.length}). ` +
        `Read each row's OWN time column for event times — do not use the current time:\n\n${csvChunk}\n\n` +
        `Return the JSON delta.`;

      const delta = await withRetry(async () => {
        const parsed = await this.analyzeRestored(caseId, state, provider, { systemPrompt: getCsvPrompt(), userPrompt, images: [] }, "csv");
        return deltaSchema.parse(parsed);
      }, retries, backoffMs);

      // Renumber event ids so chunked imports don't overwrite each other (merge
      // dedupes forensic events by id, and each batch independently emits e1, e2…).
      const renumbered = {
        ...delta,
        forensicEvents: applySeverityFloor(delta.forensicEvents ?? [], opts.minSeverity).map((e) => ({ ...e, id: `${opts.idPrefix}e${++evSeq}`, sources: e.sources?.length ? e.sources : [detectTool(opts.label) ?? "CSV import"] })),
      };

      state = mergeDelta(state, renumbered, {
        windowSequence: -(b + 1), // negative: distinguishes import batches from capture windows
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label], // evidence traceability: the CSV file
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(b + 1, batches.length);
    }
    return state;
  }

  // Import an uploaded generic log file (firewall logs, syslog, sshd, IIS, etc.)
  // as evidence. Logs are mostly repetition, so we DEDUPLICATE deterministically
  // first (aggregateLogLines collapses near-identical lines into counted patterns),
  // then ask the model to triage the PATTERNS — emitting one aggregated forensic
  // event only for the security-relevant ones and skipping routine noise. This
  // keeps the timeline signal-rich and cuts the analysis to ~one AI call.
  // Findings/TTPs/attacker-path come afterwards from synthesize().
  async analyzeLog(
    caseId: string,
    logText: string,
    opts: {
      label: string;             // evidence label shown as the event source (stored filename)
      idPrefix: string;          // unique per import (e.g. "l3") so event ids never collide
      importedAt: string;        // ISO time used for timeline/firstSeen context
      patternsPerBatch?: number; // how many distinct patterns to triage per AI call
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const provider = this.requireProvider("log analysis");
    const { lines } = parseLogLines(logText);
    if (lines.length === 0) return this.opts.stateStore.load(caseId);

    // Collapse the raw lines into distinct, counted patterns (most frequent first).
    const templates = aggregateLogLines(lines);
    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;

    let state = await this.opts.stateStore.load(caseId);
    let evSeq = 0; // running counter → globally unique forensic-event ids for this import

    // Batch by BOTH the pattern cap and a token budget — a few patterns with very long
    // examples shouldn't form a prompt that overflows the model context.
    const renderPattern = (t: typeof templates[number]) =>
      `×${t.count} ${t.firstTimestamp ?? ""} ${t.lastTimestamp ?? ""} ${t.example}`;
    const logOverhead = estimateTokens(getLogPrompt()) + estimateTokens(buildStateSummary(state)) + 96;
    const patternBudget = Math.max(0, inputTokenBudget() - logOverhead);
    const batches = batchByBudget(templates, opts.patternsPerBatch ?? 120, renderPattern, patternBudget);

    for (let b = 0; b < batches.length; b++) {
      // Present each pattern with its occurrence count, time span, and an example.
      const patternText = batches[b]
        .map((t, i) =>
          `[p${i + 1}] ×${t.count}` +
          (t.firstTimestamp ? ` first=${t.firstTimestamp}` : "") +
          (t.lastTimestamp && t.lastTimestamp !== t.firstTimestamp ? ` last=${t.lastTimestamp}` : "") +
          `\n     e.g. ${t.example}`,
        )
        .join("\n");
      const userPrompt =
        `${buildStateSummary(state)}\n\nDEDUPLICATED LOG PATTERNS (source: ${opts.label}; ` +
        `batch ${b + 1}/${batches.length}; ${lines.length} raw line(s) → ${templates.length} pattern(s)). ` +
        `Emit an aggregated event ONLY for security-relevant patterns; skip routine noise:\n\n${patternText}\n\n` +
        `Return the JSON delta.`;

      const delta = await withRetry(async () => {
        const parsed = await this.analyzeRestored(caseId, state, provider, { systemPrompt: getLogPrompt(), userPrompt, images: [] }, "log");
        return deltaSchema.parse(parsed);
      }, retries, backoffMs);

      const renumbered = {
        ...delta,
        forensicEvents: applySeverityFloor(delta.forensicEvents ?? [], opts.minSeverity).map((e) => ({ ...e, id: `${opts.idPrefix}e${++evSeq}`, sources: e.sources?.length ? e.sources : [detectTool(opts.label) ?? "Log import"] })),
      };

      state = mergeDelta(state, renumbered, {
        windowSequence: -(b + 1),
        timestamp: opts.importedAt,
        sourceScreenshots: [opts.label],
      });
      await this.opts.stateStore.save(state);
      this.opts.onState?.(state);
      opts.onProgress?.(b + 1, batches.length);
    }
    return state;
  }

  // Import a THOR (Nextron) scanner report in JSON-Lines format. Unlike the CSV/log
  // paths this is DETERMINISTIC — THOR's JSON is structured and stable, so each
  // finding maps straight to a forensic event + IOCs with NO AI extraction call.
  // Scan-lifecycle/info noise (module init, "Info" level) is dropped by default.
  // Findings/attacker-path still come from a later synthesize().
  async importThor(
    caseId: string,
    jsonText: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "t3") so ids never collide
      importedAt: string;
      thor?: ThorImportOptions;  // filtering overrides (dropInfo, dropLifecycleModules…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseThorReport(jsonText, opts.thor);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    // Assign stable, collision-free ids and validate the delta against the schema
    // (fills defaults like relatedFindingIds). No model call — purely structural.
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({ ...e, id: `${opts.idPrefix}e${i + 1}` })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `THOR import: ${parsed.kept} finding(s) kept, ${parsed.dropped} info/lifecycle row(s) dropped` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a SIEM / EDR JSON export (Elastic/Kibana, Splunk, an EDR console, a raw
  // winlogbeat dump…). Like THOR, the mapping is DETERMINISTIC (no AI call): the
  // container is unwrapped, Windows/Sysmon events get a per-EID mapping, other records
  // fall back to field auto-detection, and repetitive events are aggregated. The
  // detected tool name (from the filename / source) tags each event's `sources`.
  async importSiem(
    caseId: string,
    jsonText: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "s3") so ids never collide
      importedAt: string;
      siem?: SiemImportOptions;  // filtering overrides (aggregate, minSeverity, maxEvents…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSiemExport(jsonText, opts.siem);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const source = detectTool(opts.label) ?? detectTool(parsed.format) ?? "SIEM import";
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [source],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `SIEM import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import Chainsaw (WithSecure) hunt output or a raw EVTX-as-JSON dump. Like THOR/SIEM
  // the mapping is DETERMINISTIC (no AI call): the embedded EVTX events get the same
  // per-EID Windows mapping as the SIEM import, and — for Chainsaw — the matched Sigma
  // rule's level drives severity while its `attack.tXXXX` tags become MITRE techniques.
  // Each event is tagged Chainsaw / EVTX as its source for cross-source correlation.
  async importChainsaw(
    caseId: string,
    jsonText: string,
    opts: {
      label: string;
      idPrefix: string;               // unique per import (e.g. "c3") so ids never collide
      importedAt: string;
      chainsaw?: ChainsawImportOptions; // filtering overrides (aggregate, minSeverity, maxEvents…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseChainsawReport(jsonText, opts.chainsaw);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const fallback = parsed.detections > 0 ? "Chainsaw" : "EVTX";
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [fallback],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `${parsed.detections > 0 ? "Chainsaw" : "EVTX"} import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.detections > 0 ? `, ${parsed.detections} rule detection(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a Hayabusa (Yamato Security) detection timeline — JSON/JSONL or CSV. Like the
  // other deterministic paths there is no AI call: the matched Sigma rule's level drives
  // severity, its title leads the description, its tactics/tags become MITRE, and IOCs /
  // asset / process-chain come from the rendered detail fields. Tagged Hayabusa as source.
  async importHayabusa(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                  // unique per import (e.g. "h3") so ids never collide
      importedAt: string;
      hayabusa?: HayabusaImportOptions;  // filtering overrides (aggregate, minSeverity, maxEvents…)
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseHayabusaTimeline(text, opts.hayabusa);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Hayabusa"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Hayabusa import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import Velociraptor native JSON output (collection results / hunt export). Like the
  // other deterministic paths there is no AI call: each row is classified (Sigma / YARA /
  // EventLog / generic) and mapped — detection rows are verdict-driven, the rest auto-detect
  // the artifact's own time + IOCs. Every event is tagged Velociraptor as its source.
  async importVelociraptor(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                       // unique per import (e.g. "v3") so ids never collide
      importedAt: string;
      velociraptor?: VelociraptorImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    // Rows often carry no _Source; use the (Velociraptor-named) filename as the fallback artifact
    // label so generic/detection events show their source — e.g. "DetectRaptor.Windows.Detection.NamedPipes".
    const rawArtifact = opts.label.replace(/^\d+_/, "").replace(/\.(json|jsonl|ndjson|csv)$/i, "");
    let artifact = rawArtifact;
    try { artifact = decodeURIComponent(rawArtifact); } catch { /* malformed %xx — keep the raw label */ }
    const parsedRaw = parseVelociraptorJson(text, { artifact, ...opts.velociraptor });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Velociraptor"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Velociraptor import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.detections > 0 ? `, ${parsed.detections} detection(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import network-monitor logs — Suricata `eve.json` and Zeek JSON (Security Onion's
  // network side). Deterministic (no AI call): the timeline is built from the detections
  // (Suricata alerts + Zeek notices); surrounding telemetry (dns/http/tls/files/conn)
  // contributes IOCs only. Events are tagged Suricata / Zeek.
  async importNetwork(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                // unique per import (e.g. "n3") so ids never collide
      importedAt: string;
      network?: NetworkImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseNetworkLogs(text, opts.network);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Suricata"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Network import (${parsed.format}): ${parsed.kept} detection event(s) from ${parsed.total} record(s)` +
        (parsed.alerts > 0 ? `, ${parsed.alerts} alert/notice(s)` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a KAPE / Eric Zimmerman Tools CSV (Prefetch, Amcache, ShimCache, LNK, JumpLists,
  // UsnJrnl, MFT, SRUM, Recycle Bin, Shellbags). Deterministic (no AI call): the EZ tool is
  // detected from the CSV header, then each row maps to a forensic event reading the
  // artifact's own time + file/hash/process IOCs. Events are tagged by artifact name.
  async importKape(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;             // unique per import (e.g. "k3") so ids never collide
      importedAt: string;
      kape?: KapeImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseKapeCsv(text, opts.kape);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [parsed.artifact],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `KAPE/${parsed.artifact} import: ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a Cyber Triage timeline export (JSONL / JSON array / CSV). Deterministic (no AI call):
  // scored rows map verdict-first (severity from the Bad/Suspicious verdict + reason keywords),
  // unscored process/task rows become Info evidence, the bulk File super-timeline is dropped
  // (unless `fileTelemetry`), and Active-Connection remote IPs become IOCs. Events tagged
  // "Cyber Triage".
  async importCybertriage(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;                  // unique per import (e.g. "ct3") so ids never collide
      importedAt: string;
      cybertriage?: CybertriageImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseCybertriage(text, opts.cybertriage);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Cyber Triage"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Cyber Triage import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.notable > 0 ? `, ${parsed.notable} scored item(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import Microsoft 365 Unified Audit Log + Entra ID (sign-in / directory audit) data.
  // Deterministic (no AI call): each record is classified (UAL / sign-in / audit) and mapped,
  // severity derived from the operation (BEC tradecraft) or Entra's own risk verdict; the
  // source IP becomes an IOC and the UPN is surfaced for the asset graph.
  async importM365(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "m3") so ids never collide
      importedAt: string;
      m365?: M365ImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseM365Audit(text, opts.m365);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Microsoft 365"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Microsoft 365 import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import AWS CloudTrail logs. Deterministic (no AI call): each API-call record is mapped,
  // severity derived from the action (IAM persistence, logging/detection tampering, S3
  // exposure, secrets access) + denied/root/console-failure bumps; the caller IP → IOC.
  async importAws(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "a3") so ids never collide
      importedAt: string;
      aws?: AwsImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseCloudTrail(text, opts.aws);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["AWS CloudTrail"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `AWS CloudTrail import: ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import GCP Cloud Audit Logs + Azure Activity Log. Deterministic (no AI call): each record
  // is routed (GCP / Azure) and mapped, severity derived from the action (+ denied bump); the
  // caller IP → IOC and the principal email is surfaced for the asset graph.
  async importCloudActivity(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;          // unique per import (e.g. "g3") so ids never collide
      importedAt: string;
      cloud?: CloudActivityImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseCloudActivity(text, opts.cloud);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Cloud Audit"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Cloud activity import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a Plaso / log2timeline super-timeline (psort CSV — dynamic or l2tcsv). Deterministic
  // (no AI call): each row is an Info evidence event read at its own time, with IOCs scraped
  // from the message (hashes/URLs/IPs) and the source file path. Tagged Plaso.
  async importPlaso(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "p3") so ids never collide
      importedAt: string;
      plaso?: PlasoImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parsePlasoCsv(text, opts.plaso);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Plaso"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Plaso import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a Linux auditd log (raw audit.log / `ausearch` record format, or an `aureport` table).
  // Deterministic (no AI call): records sharing a serial collapse into one logical event, mapped
  // to severity/MITRE by record type (logins, account/group mgmt, sudo, SELinux denials, audit-config
  // tampering), bumped on a failed auth or a suspicious command. Read at the audit() epoch. Tagged auditd.
  async importAuditd(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "ad3") so ids never collide
      importedAt: string;
      auditd?: AuditdImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseAuditdLog(text, opts.auditd);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["auditd"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `auditd import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a systemd-journald structured log (`journalctl -o json` / `-o json-pretty`). Deterministic
  // (no AI call): each entry is read at its own time (_SOURCE/__REALTIME µs epoch), severity derived
  // from PRIORITY then bumped from the message (sshd auth, sudo, useradd, kernel), with IOCs scraped
  // from _EXE/_COMM and the MESSAGE. Tagged journald.
  async importJournald(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "jd3") so ids never collide
      importedAt: string;
      journald?: JournaldImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseJournald(text, opts.journald);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["journald"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `journald import: ${parsed.kept} event(s) from ${parsed.total} entr(y/ies)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a sysdig / Falco export (Falco alert JSON and/or sysdig `-j` event JSON). Deterministic
  // (no AI call): Falco rule hits are the DETECTIONS (verdict-first: priority → severity, tags →
  // MITRE) and surface on the timeline; raw sysdig syscall events are telemetry → Info evidence;
  // both contribute proc/file/network IOCs. Tagged Falco / sysdig.
  async importSysdig(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "sd3") so ids never collide
      importedAt: string;
      sysdig?: SysdigImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSysdig(text, opts.sysdig);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["sysdig"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `sysdig/Falco import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.alerts > 0 ? `, ${parsed.alerts} Falco alert(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import Wazuh SIEM/EDR alert exports (alerts.json / NDJSON / API export). Deterministic
  // (no AI call): rule.level drives severity (≥13 Critical, ≥10 High, ≥7 Medium, else Info),
  // rule.mitre.technique → MITRE, agent.name → asset, data.srcip/dstip/md5/sha256/url → IOCs.
  async importWazuh(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "w3") so ids never collide
      importedAt: string;
      wazuh?: WazuhImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseWazuhAlerts(text, opts.wazuh);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Wazuh"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Wazuh import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)` +
        (parsed.hostname ? ` (host ${parsed.hostname})` : ""),
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a malware-sandbox detonation report (CAPEv2 or CrowdStrike Falcon Sandbox).
  // Deterministic (no AI call): the sample verdict + each behavioural signature map to events
  // (severity from the report's own score/verdict, MITRE from its ATT&CK), and every
  // dropped/extracted file hash + network host/domain/URL is harvested as an IOC.
  async importSandbox(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "sb3") so ids never collide
      importedAt: string;
      sandbox?: SandboxImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseSandboxReport(text, opts.sandbox);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Sandbox"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Sandbox import (${parsed.format}): ${parsed.kept} event(s)` +
        (parsed.signatures > 0 ? `, ${parsed.signatures} signature(s)` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import memory-forensics tool output (Volatility 3 or Rekall). Deterministic (no AI call): each
  // plugin table is identified by its columns and mapped — pslist/psscan/pstree → process-tree
  // events (with parent→child links), netscan/netstat → network-connection events (+ foreign IP/
  // port IOCs), malfind → High injected-code events (ATT&CK T1055), cmdline → command-line events
  // (bumped on LOLBin/encoded tradecraft), svcscan/modules → service/driver evidence. Tagged
  // "Volatility" / "Rekall" for cross-source correlation; reads the artifact's own time.
  async importMemory(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "mem3") so ids never collide
      importedAt: string;
      memory?: MemoryImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseMemory(text, { ...opts.memory, filename: opts.label });
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const tool = parsed.tool || "Volatility";
    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : [tool],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Memory import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} row(s) across ${parsed.tables} plugin(s)` +
        (parsed.injected > 0 ? `, ${parsed.injected} injected-code hit(s)` : "") +
        (parsed.connections > 0 ? `, ${parsed.connections} connection(s)` : "") +
        (parsed.groups > parsed.kept ? `, ${parsed.groups - parsed.kept} group(s) over the cap` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import an email artifact (.eml RFC 2822, or best-effort .msg). Deterministic (no AI call):
  // ONE forensic event dated at the message's own Date: header, severity DERIVED from the email's
  // SPF/DKIM/DMARC verdict + sender heuristics; URLs, sender/reply-to domains, originating IP and
  // attachment names/hashes become IOCs. Covers ATT&CK T1566 (Phishing). Tagged "Email".
  async importEmail(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "em3") so ids never collide
      importedAt: string;
      email?: EmailImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseEmail(text, opts.email);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["Email"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `Email import (${parsed.format}): ${parsed.kept} event(s)` +
        (parsed.subject ? ` — "${parsed.subject.slice(0, 80)}"` : "") +
        `, ${parsed.iocs.length} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import a TheHive 5 case, alert, or observable export. Deterministic (no AI call):
  // case/alert records → forensic events (severity from TheHive's own 1–4 scale, MITRE from
  // ATT&CK-tagged tags, TLP/PAP labels prepended); observable records → IOCs by dataType.
  async importTheHive(
    caseId: string,
    text: string,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "th3") so ids never collide
      importedAt: string;
      thehive?: TheHiveImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseTheHive(text, opts.thehive);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["TheHive"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `TheHive import (${parsed.format}): ${parsed.kept} event(s) from ${parsed.total} record(s)` +
        (parsed.observables > 0 ? `, ${parsed.observables} observable(s)` : "") +
        `, ${parsed.iocCount} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Import an existing DFIR-IRIS case (issue #88) — the reverse of the IRIS push. Takes the raw
  // case rows already fetched from the IRIS API (analysis/irisImport.ts parses them deterministically,
  // NO AI call): timeline → forensic events, IOCs → IOCs, assets → evidence events. All feed the
  // same forensic timeline via mergeDelta, exactly like the other importers.
  async importIris(
    caseId: string,
    data: IrisCaseData,
    opts: {
      label: string;
      idPrefix: string;            // unique per import (e.g. "iris3") so ids never collide
      importedAt: string;
      iris?: IrisImportOptions;
      minSeverity?: Severity;    // gate-aware import floor (unified Import button) — see applySeverityFloor
      onProgress?: (done: number, total: number) => void;
    },
  ): Promise<InvestigationState> {
    const parsedRaw = parseIrisCase(data, opts.iris);
    const parsed = { ...parsedRaw, events: applySeverityFloor(parsedRaw.events, opts.minSeverity) };
    if (parsed.events.length === 0 && parsed.iocs.length === 0) return this.opts.stateStore.load(caseId);

    const raw = {
      findings: [],
      iocs: parsed.iocs.map((c, i) => ({ id: `${opts.idPrefix}i${i + 1}`, type: c.type, value: c.value })),
      mitreTechniques: [],
      forensicEvents: parsed.events.map((e, i) => ({
        ...e, id: `${opts.idPrefix}e${i + 1}`, sources: e.sources?.length ? e.sources : ["DFIR-IRIS"],
      })),
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: `DFIR-IRIS import (${parsed.caseName ?? `case #${parsed.irisCaseId ?? "?"}`}): ` +
        `${parsed.kept} event(s) from ${parsed.timelineCount} timeline + ${parsed.assetCount} asset(s)` +
        `, ${parsed.iocCount} IOC(s)`,
      summary: "",
    };
    const delta = deltaSchema.parse(raw);

    let state = await this.opts.stateStore.load(caseId);
    state = mergeDelta(state, delta, {
      windowSequence: -1,
      timestamp: opts.importedAt,
      sourceScreenshots: [opts.label],
    });
    await this.opts.stateStore.save(state);
    this.opts.onState?.(state);
    opts.onProgress?.(1, 1);
    return state;
  }

  // Holistic pass: read the whole forensic timeline and produce findings, MITRE
  // mapping, and the attacker-path narrative. Text-only (no images), one call.
  // Answer a free-form analyst question about the case from its evidence (single-shot, no
  // state change). Returns a grounded answer + status + collection guidance (`pointer`).
  async ask(caseId: string, question: string): Promise<AskAnswer> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("case questions");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = Number(process.env.DFIR_AI_SYNTH_MAX_EVENTS) || 300;
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = loaded.findings.slice(0, 150).map((f) => `[${f.id}] [${f.severity}] ${f.title}`).join("\n") || "(none)";
    const questionsText = loaded.keyQuestions.map((q) => `- ${q.question}${q.answer ? ` → ${q.answer}` : " (open)"}`).join("\n") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);

    // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
    const askOverhead = estimateTokens(getAskPrompt())
      + estimateTokens(contextBlock + (loaded.attackerPath || "") + findingsText + questionsText + question) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - askOverhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `CURRENT QUESTIONS:\n${questionsText}\n\n` +
      `ANALYST QUESTION: ${question.trim()}\n\nAnswer it as JSON.`;

    return withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getAskPrompt(), userPrompt, images: [] }, "ask");
      return askSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Propose proactive Velociraptor VQL fleet-hunts from the synthesized findings (issue #57).
  // Single text-only AI call; EPHEMERAL like ask()/executiveSummary() — it does NOT mutate state.
  // The analyst reviews each hunt's VQL + rationale, then one-click deploys it through the existing
  // launchHunt flow (POST /velociraptor/hunt). Returns [] without an AI call on an empty case.
  async suggestHunts(caseId: string): Promise<HuntSuggestion[]> {
    const provider = this.opts.velociraptorProvider ?? this.opts.synthesisProvider ?? this.requireProvider("hunt suggestions");
    const loaded = await this.opts.stateStore.load(caseId);
    if (!hasHuntMaterial(loaded)) return [];   // nothing to pivot on — don't spend a call

    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = Number(process.env.DFIR_AI_SYNTH_MAX_EVENTS) || 300;
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = renderHuntFindings(loaded.findings);
    const iocText = renderHuntIocs(loaded.iocs);
    const techText = loaded.mitreTechniques.map((t) => `${t.id} ${t.name}`).join(", ") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);

    // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
    const overhead = estimateTokens(getHuntSuggestPrompt())
      + estimateTokens(contextBlock + findingsText + iocText + techText + (loaded.attackerPath || "")) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `ATT&CK TECHNIQUES: ${techText}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `PIVOTABLE INDICATORS:\n${iocText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `Propose the fleet-hunts as JSON.`;

    const limit = Number(process.env.DFIR_HUNT_SUGGEST_MAX) || HUNT_SUGGEST_MAX_DEFAULT;
    return withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getHuntSuggestPrompt(), userPrompt, images: [] }, "suggest-hunts");
      const { suggestions } = huntSuggestionsResponseSchema.parse(parsed);
      return sanitizeHuntSuggestions(suggestions, limit);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Memory-forensics "Next-Step" agent (issue #101). The case already has Volatility 3 / Rekall output
  // imported as forensic events; read that memory evidence (the process tree, connections, malfind,
  // command lines, services), identify the anomalies, and propose the EXACT next Volatility 3 command
  // the analyst should run to dig deeper. Single text-only AI call; EPHEMERAL like ask()/suggestHunts()
  // — it does NOT mutate state. Returns [] without an AI call when the case has no memory evidence.
  async suggestMemoryNextSteps(caseId: string): Promise<MemoryNextStep[]> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("memory next-step suggestions");
    const loaded = await this.opts.stateStore.load(caseId);
    if (!hasMemoryMaterial(loaded)) return [];   // no Volatility/Rekall evidence — don't spend a call

    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);
    const memEvents = scopedEvents.filter(isMemoryEvent);
    if (!memEvents.length) return [];            // all memory evidence is out-of-scope / legitimate

    const pluginsText = memoryPluginsPresent(memEvents).join(", ") || "(unknown)";

    // Trim the memory evidence so the whole prompt fits the model context (the rest is fixed overhead).
    const renderEvent = (e: ForensicEvent) =>
      `[${e.severity}] ${(e.description ?? "").replace(/\s+/g, " ").trim().slice(0, 300)}`;
    const overhead = estimateTokens(getMemoryNextStepPrompt()) + estimateTokens(pluginsText) + 300;
    const fit = fitItemsToBudget(memEvents, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    const evidenceText = renderMemoryEvidence(memEvents, Math.max(1, fit));

    const userPrompt =
      `ALREADY-IMPORTED MEMORY PLUGINS (prefer suggesting plugins NOT in this list where they advance the case): ${pluginsText}\n\n` +
      `MEMORY EVIDENCE (${memEvents.length} Volatility/Rekall events, worst-severity first):\n${evidenceText}\n\n` +
      `Propose the next Volatility 3 commands as JSON.`;

    const limit = Number(process.env.DFIR_MEMORY_NEXTSTEP_MAX) || MEMORY_NEXTSTEP_MAX_DEFAULT;
    return withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getMemoryNextStepPrompt(), userPrompt, images: [] }, "memory-next-steps");
      const { suggestions } = memoryNextStepResponseSchema.parse(parsed);
      return sanitizeMemoryNextSteps(suggestions, limit);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Hypothesise what an attacker did during the timeline's SILENT periods (issue #96). Builds on the
  // deterministic gap detector: detect the suspicious gaps, then make ONE text-only AI call that reads
  // each gap's bounding events (before/after the silence) and infers the attacker activity that fits.
  // Each gap is also paired with the DETERMINISTIC shadow-artifact collections (USN journal, SRUM,
  // Prefetch, Amcache, …) that reconstruct the missing window — so even a gap the model skips still
  // carries deployable Velociraptor collections. EPHEMERAL like ask()/suggestHunts(): no state change.
  // Returns an empty result (no AI spend) when the timeline has no flagged gaps.
  async hypothesizeGaps(caseId: string): Promise<GapHypothesesResult> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("gap hypothesis");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    // Use the SAME gap detection (and thresholds) the panel/report use, so the analyst hypothesises
    // about exactly the gaps they see flagged.
    const gaps = detectTimelineGaps(scopedEvents, gapEnvOptions());
    if (!hasGapMaterial(gaps)) return { hypotheses: [], caveat: GAP_HYPOTHESIS_CAVEAT };

    const cap = Number(process.env.DFIR_GAP_HYPOTHESIS_MAX) || GAP_HYPOTHESIS_MAX_DEFAULT;
    const focusGaps = gaps.slice(0, Math.max(1, Math.floor(cap)));   // worst-first → keep the most suspicious
    const around = Number(process.env.DFIR_GAP_HYPOTHESIS_CONTEXT) || SURROUNDING_EVENTS_DEFAULT;
    const surroundByGapId = new Map(focusGaps.map((g) => [g.id, surroundingEvents(g, scopedEvents, around)]));
    const validGapIds = new Set(focusGaps.map((g) => g.id));

    const gapsText = renderGapsForPrompt(focusGaps, surroundByGapId);
    // The shadow-artifact catalog the model ranks against (id → what it reconstructs). The catalog
    // supplies the actual collection VQL deterministically; the model only picks the relevant ids.
    const artifactsText = SHADOW_ARTIFACTS.map((a) => `- ${a.id}: ${a.name} — ${a.reconstructs}`).join("\n");
    const userPrompt =
      `SHADOW ARTIFACTS (reference recommendedArtifactIds ONLY from these ids):\n${artifactsText}\n\n` +
      `TIMELINE GAPS (${focusGaps.length} of ${gaps.length} flagged; worst-first) with their surrounding events:\n\n` +
      `${gapsText}\n\n` +
      `Hypothesise the attacker activity for each gap as JSON.`;

    const aiHypotheses = await withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getGapHypothesisPrompt(), userPrompt, images: [] }, "hypothesize-gaps");
      const { hypotheses } = gapHypothesesResponseSchema.parse(parsed);
      return sanitizeGapHypotheses(hypotheses, validGapIds, focusGaps.length);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);

    return buildGapHypotheses(aiHypotheses, focusGaps, surroundByGapId);
  }

  // Propose a Velociraptor hunt for each ENDPOINT-related PLAYBOOK task (issue #70). Single text-only
  // AI call; EPHEMERAL like suggestHunts() — it does NOT mutate state. The deploy MODE is decided here
  // deterministically from the case's observed endpoints: a task tied to exactly one host → a single
  // client COLLECTION on it; otherwise → a fleet HUNT. The playbook `tasks` are passed in by the route
  // (the pipeline has no PlaybookStore). Returns [] without an AI call when there's no endpoint task.
  async suggestPlaybookHunts(caseId: string, tasks: PlaybookTask[], availableArtifacts: string[] = [], opts?: { excludeVql?: string }): Promise<PlaybookHuntSuggestion[]> {
    const provider = this.opts.velociraptorProvider ?? this.opts.synthesisProvider ?? this.requireProvider("playbook hunt suggestions");
    const loaded = await this.opts.stateStore.load(caseId);
    if (!hasPlaybookHuntMaterial(loaded, tasks)) return [];   // empty/closed playbook → don't spend a call

    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const endpointsByTaskId = buildTaskEndpointsMap(loaded, tasks);
    const endpoints = knownEndpoints(loaded);
    const tasksText = renderPlaybookHuntTasks(tasks, endpointsByTaskId);
    const endpointsText = renderKnownEndpoints(endpoints);
    // The server's REAL CLIENT artifacts (passed in by the route) — the model may reference an
    // Artifact.<Name> only from this list (otherwise it hallucinates a name that won't compile).
    const artifactsText = renderAvailableArtifacts(availableArtifacts, Number(process.env.DFIR_PBHUNT_MAX_ARTIFACTS) || 150);

    // This call hunts PER TASK (grounded by the tasks + findings + IOCs + endpoints), so it does NOT
    // need the full synthesis timeline — a smaller stratified event sample keeps the signal while
    // cutting the prompt (the timeline dominates it). A leaner prompt is faster + cheaper and shrinks
    // the window for a transient provider transport failure on a long generation. Tune via
    // DFIR_PBHUNT_MAX_EVENTS (default 120, well below synthesis's 300).
    const max = Number(process.env.DFIR_PBHUNT_MAX_EVENTS) || 120;
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}]${e.asset ? ` <${e.asset}>` : ""} ${e.description.slice(0, 240)}`;
    const findingsText = renderHuntFindings(loaded.findings);
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);

    // Trim the timeline so the whole prompt fits the model context (the rest is fixed overhead).
    const overhead = estimateTokens(getPlaybookHuntPrompt())
      + estimateTokens(contextBlock + tasksText + endpointsText + artifactsText + findingsText + (loaded.attackerPath || "")) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const excludeNote = opts?.excludeVql
      ? `ALREADY SUGGESTED (this VQL was already shown to the analyst — generate something DIFFERENT that investigates from a different angle or uses different VQL plugins):\n${opts.excludeVql}\n\n`
      : "";
    const userPrompt =
      contextBlock +
      `KNOWN ENDPOINTS (hosts — pick a targetHost ONLY from these): ${endpointsText}\n\n` +
      `AVAILABLE VELOCIRAPTOR ARTIFACTS (reference Artifact.<Name> ONLY if <Name> is in this list — else use a raw plugin):\n${artifactsText}\n\n` +
      `PLAYBOOK TASKS:\n${tasksText}\n\n` +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      excludeNote +
      `Propose the per-task hunts as JSON.`;

    const limit = Number(process.env.DFIR_PBHUNT_SUGGEST_MAX) || PLAYBOOK_HUNT_SUGGEST_MAX_DEFAULT;
    return withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getPlaybookHuntPrompt(), userPrompt, images: [] }, "suggest-playbook-hunts");
      const { suggestions } = playbookHuntResponseSchema.parse(parsed);
      return sanitizePlaybookHuntSuggestions(suggestions, endpointsByTaskId, endpoints, limit);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  // Generate a chronological prose narrative of the incident for management/stakeholders
  // (single AI call). The result is saved to state.narrativeTimeline so it persists and
  // appears in the report and dashboard immediately without a manual copy step.
  async generateNarrative(caseId: string): Promise<{ narrativeTimeline: string }> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("narrative generation");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = Number(process.env.DFIR_AI_SYNTH_MAX_EVENTS) || 300;
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = loaded.findings.slice(0, 150).map((f) => `[${f.severity}] ${f.title}`).join("\n") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);

    const narrativePrompt = getNarrativePrompt();
    const overhead = estimateTokens(narrativePrompt)
      + estimateTokens(contextBlock + (loaded.attackerPath || "") + findingsText) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `Write the narrative timeline as JSON.`;

    const narrativeSchema = z.object({ narrativeTimeline: z.string().catch("") });
    const result = await withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: narrativePrompt, userPrompt, images: [] }, "narrative");
      return narrativeSchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);

    // Re-read state before saving so imports/edits that arrived during the AI call aren't clobbered.
    const fresh = await this.opts.stateStore.load(caseId);
    await this.opts.stateStore.save({ ...fresh, narrativeTimeline: result.narrativeTimeline });
    return result;
  }

  // Generate a management-facing executive summary of the case (single-shot, no state change).
  // Text-only over the synthesized digest, like ask(); returns plain prose for the analyst to
  // review and save into the report's executive-summary section.
  async executiveSummary(caseId: string): Promise<ExecSummary> {
    const provider = this.opts.synthesisProvider ?? this.requireProvider("executive summary");
    const loaded = await this.opts.stateStore.load(caseId);
    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(filterEventsByScope(loaded.forensicTimeline, scope), markers);

    const max = Number(process.env.DFIR_AI_SYNTH_MAX_EVENTS) || 300;
    let events = selectSynthesisEvents(scopedEvents, max);
    const renderEvent = (e: ForensicEvent) =>
      `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;
    const findingsText = loaded.findings.slice(0, 150).map((f) => `[${f.severity}] ${f.title}`).join("\n") || "(none)";
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(loaded, scopedEvents, kevCatalog);

    const overhead = estimateTokens(getExecSummaryPrompt())
      + estimateTokens(contextBlock + (loaded.attackerPath || "") + findingsText) + 300;
    const fit = fitItemsToBudget(events, renderEvent, Math.max(0, inputTokenBudget() - overhead));
    if (fit < events.length) events = selectSynthesisEvents(scopedEvents, fit);
    const timelineText = events.map(renderEvent).join("\n") || "(no events yet)";

    const userPrompt =
      contextBlock +
      `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
      `FINDINGS:\n${findingsText}\n\n` +
      `FORENSIC TIMELINE (${scopedEvents.length} in-scope events):\n${timelineText}\n\n` +
      `Write the executive summary as JSON.`;

    return withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, loaded, provider, { systemPrompt: getExecSummaryPrompt(), userPrompt, images: [] }, "exec-summary");
      return execSummarySchema.parse(parsed);
    }, this.opts.retries ?? 3, this.opts.backoffMs ?? 500);
  }

  async synthesize(caseId: string, opts: { force?: boolean } = {}): Promise<InvestigationState> {
    const synthProvider = this.opts.synthesisProvider ?? this.requireProvider("synthesis");
    const loaded = await this.opts.stateStore.load(caseId);
    if (loaded.forensicTimeline.length === 0) return loaded;

    // Cross-source correlation FIRST: collapse events that describe the same artifact
    // (same hash, or same path within a time window) reported by different tools — e.g.
    // a Velociraptor alert and a THOR alert about one downloaded file — into a single
    // corroborated event. This dedups the timeline AND means one finding (with both tools
    // as evidence) instead of two. Idempotent, so repeated synthesis is stable. The
    // correlated timeline is persisted below.
    const windowSeconds = Number(process.env.DFIR_CORRELATE_WINDOW_S);
    const state: InvestigationState = {
      ...loaded,
      forensicTimeline: correlateEvents(loaded.forensicTimeline, Number.isFinite(windowSeconds) ? { windowSeconds } : {}),
    };

    const markers = this.opts.legitimateStore ? await this.opts.legitimateStore.load(caseId) : [];

    // Scope: only events inside the investigation window feed synthesis, so
    // findings/IOCs/attacker-path/questions reflect only in-scope activity.
    // Then drop events the client confirmed legitimate so the model never derives
    // conclusions from benign activity (the raw events stay in state — reversible).
    const scope = this.opts.scopeStore ? await this.opts.scopeStore.load(caseId) : NO_SCOPE;
    const scopedEvents = filterLegitimateEvents(
      filterEventsByScope(state.forensicTimeline, scope),
      markers,
    );

    // Bound the prompt for large imports (e.g. THOR: hundreds of events + auto-findings).
    // Send the MOST SEVERE events (then most recent) up to a cap, and truncate each
    // description — this keeps the request affordable (avoids OpenRouter 402 on a giant
    // request) and inside the model's context. The deterministic high-severity backfill
    // still creates findings for any Critical/High event NOT shown here (eligibleIds below
    // is the full scoped set), so capping the prompt never loses a severe detection.
    const SYNTH_MAX_EVENTS = Number(process.env.DFIR_AI_SYNTH_MAX_EVENTS) || 300;
    // Stratified selection: all Critical/High + the earliest (initial-access) + an even
    // time-spread sample, chronologically — better kill-chain coverage than severity-only.
    let promptEvents = selectSynthesisEvents(scopedEvents, SYNTH_MAX_EVENTS);

    // Analyst notebook context: when both notebookStore and aiControlStore are wired and the
    // analyst has opted in (includeNotebook: true in ai-control.json), append the notebook
    // entries to the synthesis prompt so the AI incorporates investigator hypotheses.
    // Loaded here (before the hash) so notebook changes also trigger a fresh synthesis.
    let notebookBlock = "";
    if (this.opts.notebookStore && this.opts.aiControlStore) {
      const aiCtrl = await this.opts.aiControlStore.load(caseId);
      if (aiCtrl.includeNotebook) {
        const notebookEntries = await this.opts.notebookStore.load(caseId);
        if (notebookEntries.length) {
          notebookBlock =
            "ANALYST NOTEBOOK (investigator hypotheses, notes, and open questions — take these into account when synthesizing findings and the attacker path):\n" +
            notebookEntries.map((e) => `[${e.type.toUpperCase()}] ${e.text}`).join("\n") +
            "\n\n";
        }
      }
    }

    // Skip-if-unchanged: hash only the STABLE INPUTS to synthesis — the in-scope timeline,
    // the IOCs (value + intel verdicts), the scope, the legitimate markers, and (when opted
    // in) the notebook entries. NOT the findings / MITRE / threads / summary, which synthesis
    // itself rewrites (including those would make two consecutive runs hash differently and
    // never skip). If the inputs are identical to the last successful run, return the saved
    // state — no AI call.
    const synthHash = createHash("sha1").update(JSON.stringify({
      ev: scopedEvents.map((e) => [e.id, e.severity, e.timestamp, e.description]),
      io: state.iocs.map((i) => [i.id, i.value, (i.enrichments ?? []).map((e) => e.verdict).join(",")]),
      sc: scope, lg: markers.map((m) => m.id),
      nb: notebookBlock,
    })).digest("hex");
    if (!opts.force && this.lastSynthHash.get(caseId) === synthHash) return loaded;

    const scopeNote = hasScope(scope)
      ? `INVESTIGATION SCOPE: only consider activity from ${scope.start ?? "the beginning"} to ${scope.end ?? "now"}. ` +
        `Events outside this window have already been removed below.\n\n`
      : "";
    // Cap the existing-findings echo too (a big import can produce 100s of auto-findings).
    const existingFindings = state.findings.slice(0, 150).map((f) => `[${f.id}] ${f.title}`).join("\n") || "(none yet)";
    const openThreads = state.openThreads
      .filter((t) => t.status === "open")
      .map((t) => `[${t.id}] ${t.description}`)
      .join("\n") || "(none open)";
    const legitimateBlock = buildLegitimateContext(markers);
    // Compact, corroborated context (compromised assets + threat-intel verdicts + KEV hits)
    // so the model grounds findings/attacker-path in structure instead of inferring blind.
    const kevCatalog = await this.getKevCatalog();
    const contextBlock = buildSynthesisContext(state, scopedEvents, kevCatalog);
    // Analyst-pinned open questions: tell the model to address each (answer when the evidence
    // now supports it) and keep them. They're re-merged into the output below so they persist.
    const pinnedQuestions = state.keyQuestions.filter((q) => q.pinned);
    const pinnedBlock = pinnedQuestions.length
      ? `OPEN QUESTIONS TO ADDRESS (include EACH in keyQuestions with the SAME id; answer with ` +
        `status/answer + supporting relatedEventIds if the evidence now supports it, else status ` +
        `"unknown" with a 'pointer' to the artifact to collect):\n` +
        pinnedQuestions.map((q) => `[${q.id}] ${q.question}`).join("\n") + "\n\n"
      : "";

    // Token budget: trim the timeline so the WHOLE prompt fits the model context — the rest
    // (context block, findings echo, system prompt) is the fixed overhead. Re-select for the
    // smaller count so the kept events stay the most important; the high-severity backfill
    // still creates findings for any Critical/High event dropped here.
    const renderEvent = (e: ForensicEvent) =>
      `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}`;
    const synthOverhead = estimateTokens(getSynthesisPrompt())
      + estimateTokens(scopeNote + contextBlock + notebookBlock + pinnedBlock + existingFindings + openThreads + legitimateBlock + (state.lastSummary || "")) + 400;
    const fit = fitItemsToBudget(promptEvents, renderEvent, Math.max(0, inputTokenBudget() - synthOverhead));
    if (fit < promptEvents.length) promptEvents = selectSynthesisEvents(scopedEvents, fit);

    const timelineText = promptEvents.map(renderEvent).join("\n");
    const truncatedNote = scopedEvents.length > promptEvents.length
      ? ` — showing ${promptEvents.length} of ${scopedEvents.length}; ${scopedEvents.length - promptEvents.length} event(s) omitted from this prompt but still in the case`
      : "";
    const userPrompt =
      scopeNote +
      contextBlock +
      notebookBlock +
      pinnedBlock +
      `FORENSIC TIMELINE (${scopedEvents.length} dated events${truncatedNote}):\n${timelineText}\n\n` +
      `EXISTING FINDINGS (update by id, do not duplicate):\n${existingFindings}\n\n` +
      `CURRENTLY OPEN THREADS (close by id in threadsClosed when the evidence resolves them):\n${openThreads}\n\n` +
      (legitimateBlock ? `${legitimateBlock}\n\n` : "") +
      `Running notes: ${state.lastSummary || "(none)"}\n\nReturn the JSON conclusions.`;

    const retries = this.opts.retries ?? 3;
    const backoffMs = this.opts.backoffMs ?? 500;
    const delta = await withRetry(async () => {
      const parsed = await this.analyzeRestored(caseId, state, synthProvider, { systemPrompt: getSynthesisPrompt(), userPrompt, images: [] }, "synthesis");
      return deltaSchema.parse(parsed);
    }, retries, backoffMs);

    // Anchor finding timestamps to the last real event time (fallback: existing state time).
    const ts = state.forensicTimeline[state.forensicTimeline.length - 1]?.timestamp || state.updatedAt;
    // Synthesis is an authoritative holistic reassessment: replace the CONCLUSIONS
    // (findings, MITRE techniques) rather than accumulate, so anything no longer
    // supported by the in-scope timeline (e.g. out-of-scope or removed events) is
    // dropped. IOCs are OBSERVED INDICATORS (often from deterministic imports like THOR
    // — 100s of hashes the text-only synthesis can't re-derive), so they are PRESERVED
    // and merged (deduped by value); scope/legitimate still filter them at projection.
    // Threads and the forensic timeline are also preserved.
    const base = { ...state, findings: [], mitreTechniques: [] };
    const merged = mergeDelta(base, delta, { windowSequence: 0, timestamp: ts, sourceScreenshots: [] });
    // Safety net: drop anything confirmed legitimate even if the model re-introduced it.
    const filtered = applyLegitimate(merged, markers);

    // Back-link forensic events to the CORRECT findings using the synthesis output
    // (each finding lists the event ids it's based on). Replaces extraction guesses.
    const surviving = new Set(filtered.findings.map((f) => f.id));
    const eventToFindings = new Map<string, string[]>();
    for (const f of delta.findings) {
      if (!surviving.has(f.id)) continue;
      for (const eid of f.relatedEventIds ?? []) {
        const arr = eventToFindings.get(eid) ?? [];
        if (!arr.includes(f.id)) arr.push(f.id);
        eventToFindings.set(eid, arr);
      }
    }
    const linked = {
      ...filtered,
      forensicTimeline: filtered.forensicTimeline.map((e) => ({ ...e, relatedFindingIds: eventToFindings.get(e.id) ?? [] })),
    };

    // Heuristic safety net: a Critical/High artifact row is almost always a finding.
    // Any in-scope, non-legitimate high-severity event that synthesis left WITHOUT a
    // finding gets one auto-created, so a severe detection can never be silently
    // missed. Restricted to the events synthesis actually considered (scopedEvents).
    const eligibleIds = new Set(scopedEvents.map((e) => e.id));
    const backfilled = backfillHighSeverityFindings(linked, eligibleIds, ts);
    // Log gap analysis (#83): a COMPLETE-silence gap — a window where every source went dark — is the
    // classic signature of cleared logs / a stopped collector, so escalate it to a finding here too.
    // Gaps are derived on read (not persisted); only the complete ones earn a persisted finding, and
    // the finding id is derived from the bounding events so re-synthesis over the same gap is idempotent.
    const gapOpts = gapEnvOptions();
    const gaps = detectTimelineGaps(scopedEvents, gapOpts);
    const gapFilled = backfillSilenceGapFindings(backfilled, gaps, ts, gapOpts.maxFindings);
    // Preserve analyst-pinned questions (synthesis replaces keyQuestions wholesale). Re-read
    // the LATEST state here, not the pre-AI snapshot, so a question added DURING the
    // seconds-long AI call isn't clobbered by this write (read-modify-write race).
    const pinnedNow = (await this.opts.stateStore.load(caseId)).keyQuestions.filter((q) => q.pinned);
    const next = pinnedNow.length
      ? { ...gapFilled, keyQuestions: mergePinnedQuestions(pinnedNow, gapFilled.keyQuestions) }
      : gapFilled;

    await this.opts.stateStore.save(next);
    this.lastSynthHash.set(caseId, synthHash);   // remember these inputs so an identical re-run skips the AI call
    // Record what this run changed (diff vs the findings that existed before the AI call) and
    // when it ran — surfaced on the dashboard. Only reached on a real run; skips return early above.
    const findingsDiff = diffFindings(loaded.findings, next.findings);
    await this.opts.synthMetaStore?.record(caseId, findingsDiff);
    // Notify on new/escalated findings (issue #58). Best-effort, fire-and-forget — never blocks or
    // fails synthesis. Only on a real run, so a skipped (unchanged) re-synthesis sends nothing.
    this.opts.onSynth?.(caseId, findingsDiff, next);
    this.opts.onState?.(next);
    return next;
  }
}
