import { describe, it, expect } from "vitest";
import { backfillScriptCommandFindings } from "../../src/analysis/scriptBlockCommandFindings.js";
import {
  SCRIPT_COMMAND_FINDING_ID_PREFIX,
  isDeterministicFindingId,
} from "../../src/analysis/responseSchema.js";
import type { Finding, ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";

// The real INC-2026-001 Phase-2 script block, trimmed; hostnames are example.com-shaped and
// LAB.INVALID is the simulation's own domain.
const BLOCK = [
  "Creating Scriptblock text (1 of 1):",
  "foreach($cmd in @('nltest /dclist:LAB.INVALID','Get-ADDomain','Get-ADUser -Filter *'," +
    "'Get-ADGroupMember \"Domain Admins\"','Get-Process','Get-GPResultantSetOfPolicy')){Invoke-Decoy $cmd}",
  "@{command='ntdsutil.exe ac in ntds ifm cr fu C:\\Users\\Public\\Music\\1';blockedBy='Windows Defender';executed=$false}",
  "@{method='Cobalt Strike psexec_psh';namedPipe='\\\\.\\pipe\\fullduplex_84';pipeCreated=$false}",
].join("\n");

function ev(p: Partial<ForensicEvent>): ForensicEvent {
  return {
    id: p.id ?? "e1",
    timestamp: p.timestamp ?? "2026-09-22T08:33:05Z",
    description: p.description ?? "DetectRaptor Evtx detection: Suspicious Powershell Commandlets (EID 4104)",
    severity: p.severity ?? "High",
    asset: p.asset ?? "ws07.example.com",
    message: p.message ?? BLOCK,
    mitreTechniques: p.mitreTechniques ?? [],
    relatedFindingIds: p.relatedFindingIds ?? [],
    sourceScreenshots: [],
    ...p,
  };
}

function finding(p: Partial<Finding>): Finding {
  return {
    id: p.id ?? "f3",
    severity: p.severity ?? "High",
    confidence: 70,
    title: p.title ?? "Credential access: mimikatz and LSASS",
    description: "…",
    relatedIocs: [],
    mitreTechniques: p.mitreTechniques ?? ["T1003.001", "T1059.001"],
    sourceScreenshots: [],
    firstSeen: "2026-09-22T08:00:00Z",
    lastUpdated: "2026-09-22T09:00:00Z",
    status: "open",
    ...p,
  };
}

function state(events: ForensicEvent[], findings: Finding[] = []): InvestigationState {
  return {
    caseId: "INC-2026-001",
    findings,
    forensicTimeline: events,
    iocs: [],
    timeline: [],
    mitreTechniques: [],
    keyQuestions: [],
    nextSteps: [],
    openThreads: [],
    uncertainties: [],
    updatedAt: "2026-09-22T09:00:00Z",
  } as unknown as InvestigationState;
}

const ts = "2026-09-22T10:00:00Z";
const all = (s: InvestigationState) => new Set(s.forensicTimeline.map((e) => e.id));

describe("backfillScriptCommandFindings", () => {
  it("raises the gap the scored case had: a row folded into an unrelated finding", () => {
    const s = state([ev({ id: "7e2", relatedFindingIds: ["f3"] })], [finding({})]);
    const next = backfillScriptCommandFindings(s, all(s), ts);
    const mint = next.findings.find((f) => f.id.startsWith(SCRIPT_COMMAND_FINDING_ID_PREFIX));
    expect(mint).toBeTruthy();
    expect(mint!.severity).toBe("Medium");
    expect(mint!.mitreTechniques).toEqual(
      expect.arrayContaining(["T1482", "T1069.002", "T1615", "T1057", "T1003.003", "T1021.002"]),
    );
    expect(mint!.title).toContain("ws07.example.com");
    expect(mint!.description).toContain("nltest /dclist:LAB.INVALID");
    expect(next.forensicTimeline[0].relatedFindingIds).toEqual(["f3", mint!.id]);
  });

  it("says the commands were present, not that they ran, and repeats the script's own qualifiers", () => {
    const s = state([ev({})]);
    const mint = backfillScriptCommandFindings(s, all(s), ts).findings[0];
    expect(mint.description).toMatch(/not that they executed/i);
    expect(mint.description).toContain("executed=$false");
    expect(mint.description).toContain("blockedBy='Windows Defender'");
  });

  it("stays quiet when a linked finding already carries the techniques", () => {
    const covered = finding({
      id: "f9",
      mitreTechniques: [
        "T1018",
        "T1482",
        "T1087.002",
        "T1069.002",
        "T1615",
        "T1057",
        "T1003.003",
        "T1021.002",
        "T1570",
      ],
    });
    const s = state([ev({ relatedFindingIds: ["f9"] })], [covered]);
    expect(backfillScriptCommandFindings(s, all(s), ts)).toBe(s);
  });

  it("claims only the techniques that are still uncovered", () => {
    const s = state(
      [ev({ relatedFindingIds: ["f9"] })],
      [finding({ id: "f9", mitreTechniques: ["T1018", "T1057", "T1615", "T1482"] })],
    );
    const mint = backfillScriptCommandFindings(s, all(s), ts).findings.find((f) =>
      f.id.startsWith(SCRIPT_COMMAND_FINDING_ID_PREFIX),
    )!;
    expect(mint.mitreTechniques).toEqual(expect.arrayContaining(["T1069.002", "T1003.003"]));
    expect(mint.mitreTechniques).not.toContain("T1057");
    expect(mint.mitreTechniques).not.toContain("T1615");
  });

  it("never mints for one routine low-specificity command on its own", () => {
    const s = state([
      ev({ message: "Creating Scriptblock text (1 of 1):\nGet-Process | Sort-Object CPU -Descending" }),
    ]);
    expect(backfillScriptCommandFindings(s, all(s), ts)).toBe(s);
  });

  it("mints for one high-specificity command alone", () => {
    const s = state([
      ev({ message: "Creating Scriptblock text (1 of 1):\nntdsutil.exe ac in ntds ifm cr fu C:\\t" }),
    ]);
    const next = backfillScriptCommandFindings(s, all(s), ts);
    expect(next.findings).toHaveLength(1);
    expect(next.findings[0].mitreTechniques).toEqual(["T1003.003"]);
  });

  it("collapses the detector views of one script block into a single finding", () => {
    const s = state([
      ev({ id: "7e2", description: "DetectRaptor Evtx detection: Commandlets (EID 4104)" }),
      ev({ id: "7e3", description: "DetectRaptor Evtx detection: Keywords2 (EID 4104)" }),
      ev({ id: "1e8", description: "Velociraptor Sigma: Potentially Malicious PwSh (EID 4104)" }),
    ]);
    const next = backfillScriptCommandFindings(s, all(s), ts);
    expect(next.findings).toHaveLength(1);
    expect(next.findings[0].id).toBe(`${SCRIPT_COMMAND_FINDING_ID_PREFIX}1e8`); // lex-first event id
    for (const e of next.forensicTimeline) expect(e.relatedFindingIds).toEqual([next.findings[0].id]);
  });

  it("keeps two different scripts, and the same script on another day, apart", () => {
    const s = state([
      ev({ id: "a1" }),
      ev({ id: "b1", timestamp: "2026-10-04T02:00:00Z" }),
      ev({ id: "c1", message: "Creating Scriptblock text (1 of 1):\nnltest /domain_trusts /all_trusts" }),
    ]);
    expect(backfillScriptCommandFindings(s, all(s), ts).findings).toHaveLength(3);
  });

  it("refuses the case's own collector, by origin and by the footprint note", () => {
    const s = state([
      ev({ id: "c1", origin: "collector" }),
      ev({
        id: "c2",
        severity: "Critical",
        description:
          "Sigma: Potential WinAPI Calls Via PowerShell (EID 4104) [DFIR collector footprint — script the Velociraptor client ran from its tool tree]",
      }),
    ]);
    expect(backfillScriptCommandFindings(s, all(s), ts)).toBe(s);
  });

  it("refuses a process row and prose that merely name the commands", () => {
    const s = state([
      ev({
        id: "p1",
        description: "Process created: nltest.exe",
        commandLine: "nltest /dclist:LAB.INVALID",
        message: "",
      }),
      ev({
        id: "p2",
        description: "Sigma rule notes: detects gpresult, Get-ADGroupMember and ntdsutil ifm usage",
        message: "",
      }),
    ]);
    expect(backfillScriptCommandFindings(s, all(s), ts)).toBe(s);
  });

  it("only reads events the synthesis scope holds", () => {
    const s = state([ev({ id: "out" })]);
    expect(backfillScriptCommandFindings(s, new Set<string>(), ts)).toBe(s);
  });

  it("is idempotent — a second run reads its own finding as coverage", () => {
    const s = state([ev({})]);
    const once = backfillScriptCommandFindings(s, all(s), ts);
    const twice = backfillScriptCommandFindings(once, all(once), ts);
    expect(twice.findings).toHaveLength(1);
    expect(twice.forensicTimeline[0].relatedFindingIds).toHaveLength(1);
  });

  it("mints an id only a deterministic pass may write", () => {
    const s = state([ev({})]);
    expect(isDeterministicFindingId(backfillScriptCommandFindings(s, all(s), ts).findings[0].id)).toBe(true);
  });
});
