// Golden dataset for the eval harness (issue #64, Phase 1).
//
// Each fixture pairs an input + a canned model response with the GOLDEN expectations the scorer asserts.
// Phase 1 ships representative CSV / log / synthesis fixtures that exercise every scorer path deterministically
// (via MockProvider). Phase 2 grows this to the ≥5-case golden set over real screenshots/CSV/logs run against
// a real provider — the fixture SHAPE here is the contract that stays stable.

import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { GoldenEvent, Thresholds } from "./scorer.js";

// A delta the MockProvider returns verbatim for an extraction call. Kept as a builder so fixtures read as data.
function delta(forensicEvents: unknown[]): string {
  return JSON.stringify({
    findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
    timelineNote: "", summary: "eval", forensicEvents,
  });
}

export interface ExtractionFixture {
  name: string;
  modality: "csv" | "log";
  input: string;
  canned: string;            // MockProvider response (Phase-1 deterministic runs); ignored in --real mode
  golden: GoldenEvent[];
  thresholds?: Thresholds;   // per-fixture override; else DEFAULT_THRESHOLDS (mock) / REAL_THRESHOLDS (--real)
}

export interface SynthesisFixture {
  name: string;
  seedEvents: ForensicEvent[];
  canned: string;
}

function ev(partial: Partial<ForensicEvent> & { id: string; timestamp: string; description: string }): ForensicEvent {
  return { severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...partial };
}

export const EXTRACTION_FIXTURES: ExtractionFixture[] = [
  {
    name: "windows-auth-csv",
    modality: "csv",
    input: [
      "Timestamp,EventID,Account,Host,Detail",
      "2026-06-01T10:00:00Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:02:00Z,4624,jdoe,WS01,successful logon after failures",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T10:00:00Z", description: "Multiple failed logons for jdoe on WS01", severity: "Medium", mitreTechniques: ["T1110"], asset: "WS01" },
      { id: "e2", timestamp: "2026-06-01T10:02:00Z", description: "Successful logon for jdoe on WS01 after brute force", severity: "High", mitreTechniques: ["T1078"], asset: "WS01" },
    ]),
    golden: [
      { timestamp: "2026-06-01T10:00:00Z", keywords: ["failed", "jdoe"], mitreTechniques: ["T1110"], asset: "WS01" },
      { timestamp: "2026-06-01T10:02:00Z", keywords: ["successful", "logon"], severity: "High", asset: "WS01" },
    ],
  },
  {
    name: "sshd-log",
    modality: "log",
    input: [
      "Jun  1 10:00:00 srv sshd[111]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:01 srv sshd[112]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:05:00 srv sshd[200]: Accepted password for root from 10.0.0.9 port 22",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T10:00:00Z", description: "SSH brute force against root from 10.0.0.9", severity: "High", mitreTechniques: ["T1110"], asset: "srv" },
    ]),
    golden: [
      { keywords: ["brute force", "root"], mitreTechniques: ["T1110"], asset: "srv" },
    ],
  },
  {
    name: "powershell-encoded-csv",
    modality: "csv",
    input: [
      "Timestamp,Host,ParentImage,Image,CommandLine",
      "2026-06-01T09:15:00Z,WS02,C:\\Windows\\System32\\WINWORD.EXE,C:\\Windows\\System32\\powershell.exe,powershell -nop -w hidden -enc SQEXpAGkAZQBz",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T09:15:00Z", description: "WINWORD spawned encoded PowerShell on WS02 (macro execution)", severity: "High", mitreTechniques: ["T1059.001"], asset: "WS02" },
    ]),
    golden: [
      { timestamp: "2026-06-01T09:15:00Z", keywords: ["powershell", "ws02"], mitreTechniques: ["T1059.001"], asset: "WS02" },
    ],
  },
  {
    name: "proxy-exfil-log",
    modality: "log",
    input: [
      "2026-06-01T13:00:00Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=1048576 user=svc_backup",
      "2026-06-01T13:00:05Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=2097152 user=svc_backup",
      "2026-06-01T13:00:10Z 10.1.1.5 GET update.microsoft.com/patch bytes_out=512 user=SYSTEM",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T13:00:00Z", description: "Large outbound transfer to mega.nz from 10.1.1.5 (svc_backup) — likely exfiltration", severity: "High", mitreTechniques: ["T1567.002"], asset: "10.1.1.5" },
    ]),
    golden: [
      { keywords: ["mega.nz", "exfil"], mitreTechniques: ["T1567.002"] },
    ],
  },
];

export const SYNTHESIS_FIXTURES: SynthesisFixture[] = [
  {
    name: "ransomware-timeline",
    seedEvents: [
      ev({ id: "s1", timestamp: "2026-06-01T11:00:00Z", description: "Ransomware note dropped on FS01", severity: "Critical", mitreTechniques: ["T1486"], asset: "FS01" }),
      ev({ id: "s2", timestamp: "2026-06-01T10:30:00Z", description: "LSASS memory dumped on DC01", severity: "High", mitreTechniques: ["T1003.001"], asset: "DC01" }),
    ],
    // Canned synthesis: one finding grounded on the seed events. The deterministic backfill guarantees any
    // uncovered high-severity event also gets a finding, so checkSynthesis coverage must pass.
    canned: JSON.stringify({
      findings: [
        { id: "f1", severity: "Critical", confidence: 90, confidenceReason: "ransom note + AV alert", title: "Ransomware deployment", description: "Files encrypted on FS01", relatedIocs: [], mitreTechniques: ["T1486"], status: "open", relatedEventIds: ["s1"] },
      ],
      iocs: [], mitreTechniques: [{ id: "T1486", name: "Data Encrypted for Impact" }],
      threadsOpened: [], threadsClosed: [], timelineNote: "", summary: "ransomware case",
    }),
  },
  {
    name: "lateral-movement-timeline",
    seedEvents: [
      ev({ id: "s1", timestamp: "2026-06-01T08:00:00Z", description: "PsExec service install on FS01 from WS02", severity: "High", mitreTechniques: ["T1021.002"], asset: "FS01" }),
      ev({ id: "s2", timestamp: "2026-06-01T08:05:00Z", description: "Admin logon (type 3) to DC01 using harvested creds", severity: "Critical", mitreTechniques: ["T1078.002"], asset: "DC01" }),
    ],
    canned: JSON.stringify({
      findings: [
        { id: "f1", severity: "High", confidence: 75, confidenceReason: "service install + source host", title: "Lateral movement via PsExec", description: "WS02 → FS01 over SMB", relatedIocs: [], mitreTechniques: ["T1021.002"], status: "open", relatedEventIds: ["s1"] },
      ],
      iocs: [], mitreTechniques: [{ id: "T1021.002", name: "SMB/Windows Admin Shares" }],
      threadsOpened: [], threadsClosed: [], timelineNote: "", summary: "lateral movement case",
    }),
  },
];
