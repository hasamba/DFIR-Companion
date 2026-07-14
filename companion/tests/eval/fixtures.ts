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
  canned: string;
  golden: GoldenEvent[];
  thresholds?: Thresholds;
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
];
