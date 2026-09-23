// A Velociraptor IOC keeps the "mentioned" mark on its way into the case (#1555).
//
// veloTextIocs marks every value it scrapes from free text "mentioned" (#1459): a domain written in a
// script block is a string its author knew, not a host anything connected to. The parser kept the
// mark; the two delta builders that hand its IOCs to mergeDelta did not — both whitelisted id, type,
// value and extractedFrom — so every scraped value reached the case as if the collector had observed
// it. importState.ts's deltaIocs is the shared fix for the same drop in other importers (#1471). The
// bulk driver's half of this is pinned in velociraptorBulk.test.ts.
//
// Every value below is synthetic (`.example.com` host, `.test` URL).
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

async function pipeline(): Promise<AnalysisPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-provenance-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  return new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore: new StateStore(caseStore),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

// A user's script block that names a URL in its text: a DetectRaptor Evtx 4104 hit.
const MENTIONING_ROW = {
  _Source: "DetectRaptor.Windows.Detection.Evtx",
  EventTime: "2026-09-22T17:28:29Z",
  Computer: "WS01",
  Detection: { Name: "T1059.001-Use of Base64 Commands", EventId: "^(4104)$", Regex: "FromBase64String" },
  Channel: "Microsoft-Windows-PowerShell/Operational",
  EventID: 4104,
  UserSID: "S-1-5-21-908230818-3748298786-230204725-1001",
  EventData: {
    MessageNumber: 1,
    MessageTotal: 1,
    ScriptBlockText: "$u = 'https://stage.mentioned-only.test/a'; [Convert]::FromBase64String($x)",
    ScriptBlockId: "9c1f9a8e-0000-4000-8000-000000000001",
    Path: "C:\\Users\\v\\stage.ps1",
  },
  Message:
    "Creating Scriptblock text (1 of 1): $u = 'https://stage.mentioned-only.test/a'; [Convert]::FromBase64String($x)",
  Fqdn: "WS01.example.com",
};

describe("importVelociraptor — a mentioned value stays mentioned in the case (#1555)", () => {
  it("carries the parser's provenance through the whole-file delta", async () => {
    const p = await pipeline();
    const state = await p.importVelociraptor("c1", JSON.stringify([MENTIONING_ROW]), {
      label: "0007_velo-hunt_DetectRaptor.Windows.Detection.Evtx.json",
      idPrefix: "7",
      importedAt: "2026-09-23T08:00:00.000Z",
    });
    const url = state.iocs.find((i) => i.value === "https://stage.mentioned-only.test/a");
    expect(url).toBeDefined();
    expect(url?.provenance).toBe("mentioned");
  });
});
