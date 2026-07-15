// Golden dataset for the eval harness (issue #64).
//
// Each fixture pairs an input + a canned model response with the GOLDEN expectations the scorer asserts.
// Mock mode drives every fixture with a MockProvider (deterministic, gates CI); `--real` drives the same
// fixtures against the env-configured model to score the CURRENT prompt's actual output.
//
// WHAT A GOLDEN MAY CONSTRAIN (learned from the first real-provider run, which scored 0/4 on extraction
// while the model's answers were substantively correct):
//   DO constrain IDENTITY + objective classification — timestamp, distinctive prose keywords, asset,
//   ATT&CK technique. These have a single right answer, so a miss is a genuine regression.
//   DON'T constrain model JUDGMENT — notably `severity`. Whether a successful logon after failures is
//   High or Medium is a defensible call either way; the scorer compares severity by EXACT equality, so
//   pinning it turns a correct extraction into a total miss (recall 0), drowning the real signal.
//   DON'T duplicate a field into `keywords` — keywords are matched against the DESCRIPTION only, so a
//   golden asking for keyword "ws02" fails a model that correctly put WS02 in the `asset` field. Use the
//   `asset` constraint for the host; keep keywords for the fact itself.
// Inputs are sized like real evidence (not 2-3 lines): a model shown a trivial snippet reasonably reports
// nothing at all, and "no events" scores recall 0 for reasons that have nothing to do with the prompt.

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
    // Password-guessing burst against one account, ending in a success — surrounded by ordinary logon
    // traffic so the brute-force run has to be picked OUT of noise rather than being the only thing present.
    name: "windows-auth-csv",
    modality: "csv",
    input: [
      "Timestamp,EventID,Account,Host,Detail",
      "2026-06-01T09:40:00Z,4624,SYSTEM,WS01,service logon",
      "2026-06-01T09:52:00Z,4624,asmith,WS03,interactive logon",
      "2026-06-01T10:00:00Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:00:11Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:00:19Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:00:27Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:00:38Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:00:46Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:00:55Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:01:04Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:01:12Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:01:31Z,4625,jdoe,WS01,failed logon (bad password)",
      "2026-06-01T10:02:00Z,4624,jdoe,WS01,successful logon after failures",
      "2026-06-01T10:14:00Z,4634,asmith,WS03,logoff",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T10:00:00Z", description: "Multiple failed logons for jdoe on WS01", severity: "Medium", mitreTechniques: ["T1110"], asset: "WS01" },
      { id: "e2", timestamp: "2026-06-01T10:02:00Z", description: "Successful logon for jdoe on WS01 after brute force", severity: "High", mitreTechniques: ["T1078"], asset: "WS01" },
    ]),
    golden: [
      // Timestamp tolerance absorbs the model anchoring on any row in the burst.
      { timestamp: "2026-06-01T10:00:00Z", keywords: ["jdoe"], mitreTechniques: ["T1110"], asset: "WS01" },
      // No `severity`: Medium vs High for "success after a brute-force run" is a defensible judgment call.
      { timestamp: "2026-06-01T10:02:00Z", keywords: ["successful"], asset: "WS01" },
    ],
  },
  {
    name: "sshd-log",
    modality: "log",
    input: [
      "Jun  1 09:58:02 srv sshd[101]: Accepted publickey for deploy from 10.0.0.4 port 51022",
      "Jun  1 10:00:00 srv sshd[111]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:01 srv sshd[112]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:03 srv sshd[113]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:04 srv sshd[114]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:06 srv sshd[115]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:08 srv sshd[116]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:09 srv sshd[117]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:11 srv sshd[118]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:13 srv sshd[119]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:14 srv sshd[120]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:16 srv sshd[121]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:00:18 srv sshd[122]: Failed password for root from 10.0.0.9 port 22",
      "Jun  1 10:05:00 srv sshd[200]: Accepted password for root from 10.0.0.9 port 22",
      "Jun  1 10:05:01 srv sshd[200]: pam_unix(sshd:session): session opened for user root by (uid=0)",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T10:00:00Z", description: "SSH brute force against root from 10.0.0.9", severity: "High", mitreTechniques: ["T1110"], asset: "srv" },
    ]),
    golden: [
      // No `timestamp`: syslog carries no year, so the resolved date depends on the importer's inference.
      // Keyword is the target account, not a wording ("brute force" vs "repeated failed passwords" both fine).
      // No `asset`: the syslog host sits in the line prefix rather than a column, and the log path does not
      // reliably lift it into `asset` — a known gap, tracked separately. Requiring it here would score an
      // otherwise-correct extraction as a total miss and bury the signal this fixture exists to give.
      { keywords: ["root"], mitreTechniques: ["T1110"] },
    ],
  },
  {
    name: "powershell-encoded-csv",
    modality: "csv",
    input: [
      "Timestamp,Host,ParentImage,Image,CommandLine",
      "2026-06-01T09:02:00Z,WS02,C:\\Windows\\explorer.exe,C:\\Program Files\\Git\\git.exe,git status",
      "2026-06-01T09:11:00Z,WS02,C:\\Windows\\explorer.exe,C:\\Windows\\System32\\WINWORD.EXE,\"WINWORD.EXE /n invoice.docm\"",
      "2026-06-01T09:15:00Z,WS02,C:\\Windows\\System32\\WINWORD.EXE,C:\\Windows\\System32\\powershell.exe,powershell -nop -w hidden -enc SQEXpAGkAZQBz",
      "2026-06-01T09:21:00Z,WS02,C:\\Windows\\explorer.exe,C:\\Windows\\System32\\notepad.exe,notepad.exe notes.txt",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T09:15:00Z", description: "WINWORD spawned encoded PowerShell on WS02 (macro execution)", severity: "High", mitreTechniques: ["T1059.001"], asset: "WS02" },
    ]),
    golden: [
      // "ws02" removed from keywords — it lives in `asset`, and keywords only match the description.
      { timestamp: "2026-06-01T09:15:00Z", keywords: ["powershell"], mitreTechniques: ["T1059.001"], asset: "WS02" },
    ],
  },
  {
    name: "proxy-exfil-log",
    modality: "log",
    input: [
      "2026-06-01T12:58:00Z 10.1.1.5 GET update.microsoft.com/patch bytes_out=512 user=SYSTEM",
      "2026-06-01T12:59:10Z 10.1.1.9 GET intranet.corp.local/home bytes_out=2048 user=asmith",
      "2026-06-01T13:00:00Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=1048576 user=svc_backup",
      "2026-06-01T13:00:05Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=2097152 user=svc_backup",
      "2026-06-01T13:00:12Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=4194304 user=svc_backup",
      "2026-06-01T13:00:21Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=8388608 user=svc_backup",
      "2026-06-01T13:00:33Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=6291456 user=svc_backup",
      "2026-06-01T13:00:48Z 10.1.1.5 CONNECT mega.nz:443 bytes_out=7340032 user=svc_backup",
      "2026-06-01T13:01:10Z 10.1.1.9 GET intranet.corp.local/docs bytes_out=4096 user=asmith",
      "2026-06-01T13:02:00Z 10.1.1.5 GET update.microsoft.com/patch bytes_out=512 user=SYSTEM",
    ].join("\n"),
    canned: delta([
      { id: "e1", timestamp: "2026-06-01T13:00:00Z", description: "Large outbound transfer to mega.nz from 10.1.1.5 (svc_backup) — likely exfiltration", severity: "High", mitreTechniques: ["T1567.002"], asset: "10.1.1.5" },
    ]),
    golden: [
      // "exfil" removed — that's the model's conclusion wording; the destination is the checkable fact.
      { keywords: ["mega.nz"], mitreTechniques: ["T1567.002"] },
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
