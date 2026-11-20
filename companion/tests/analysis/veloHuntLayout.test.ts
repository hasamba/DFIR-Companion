import { describe, it, expect } from "vitest";
import { planHuntExports, huntSkipSummary } from "../../src/analysis/veloHuntLayout.js";
import { assetHostFromDropRelpath, clientFolderHost } from "../../src/analysis/assetHost.js";
import { veloArtifactFromLabel } from "../../src/analysis/ingest/velociraptorFileImport.js";
import { huntTree, type HuntLayout } from "../helpers/huntExportFixture.js";

// #2714: one copy of each artifact is imported, by artifact rather than by layout.

const plan = (layout: HuntLayout, prefix = "") => {
  const plans = planHuntExports(Object.keys(huntTree(layout, prefix)));
  expect(plans).toHaveLength(1);
  return plans[0];
};
const importPaths = (layout: HuntLayout) => plan(layout).imports.map((i) => i.path);

describe("planHuntExports (#2714)", () => {
  it("per-client + hunt-wide + CSV: imports only the per-client JSON", () => {
    const p = plan("full", "Hunt1");
    expect(p.root).toBe("Hunt1");
    expect(p.imports).toHaveLength(9);
    expect(p.imports.every((i) => !i.huntWide && i.path.endsWith(".json"))).toBe(true);
    const reasons = Object.fromEntries(p.skips.map((s) => [s.path, s.reason]));
    expect(reasons["Hunt1/hunt_info.json"]).toBe("metadata");
    expect(reasons["Hunt1/WS-ALPHA-C.0000000000000001/client_info.json"]).toBe("metadata");
    expect(reasons["Hunt1/WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.csv"]).toBe("csv-twin");
    expect(reasons["Hunt1/results/All Windows.System.Pslist.json"]).toBe("hunt-wide-copy");
    expect(reasons["Hunt1/results/All Windows.System.Pslist.csv"]).toBe("hunt-wide-copy");
    expect(p.members).toHaveLength(Object.keys(huntTree("full")).length);
  });

  it("per-client JSON only", () => {
    expect(importPaths("perClientJson")).toHaveLength(9);
  });

  it("hunt-wide only: imports the All <Artifact>.json files", () => {
    const p = plan("huntWide");
    expect(p.root).toBe("");
    expect(p.imports.map((i) => [i.path, i.artifact, i.huntWide])).toEqual([
      ["results/All Windows.Network.Netstat.json", "Windows.Network.Netstat", true],
      ["results/All Windows.Sys.Users%2FUsers.json", "Windows.Sys.Users%2FUsers", true],
      ["results/All Windows.System.Pslist.json", "Windows.System.Pslist", true],
    ]);
  });

  it("CSV only for one artifact: its per-client CSVs import, the hunt-wide CSV is skipped", () => {
    const p = plan("csvOnlyUsers");
    const users = p.imports.filter((i) => i.artifact === "Windows.Sys.Users%2FUsers");
    expect(users).toHaveLength(3);
    expect(users.every((i) => i.path.endsWith(".csv") && !i.huntWide)).toBe(true);
    expect(p.skips).toContainEqual({
      path: "results/All Windows.Sys.Users%2FUsers.csv",
      reason: "hunt-wide-copy",
    });
  });

  it("a hunt-wide JSON beats per-client CSVs of the same artifact", () => {
    const [p] = planHuntExports([
      "hunt_info.json",
      "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.csv",
      "results/All Windows.System.Pslist.json",
    ]);
    expect(p.imports.map((i) => i.path)).toEqual(["results/All Windows.System.Pslist.json"]);
    expect(p.skips.find((s) => s.path.endsWith(".csv"))?.reason).toBe("csv-twin");
  });

  it("leaves files that are not hunt members alone", () => {
    const paths = [
      "hunt_info.json",
      "WS-ALPHA-C.0000000000000001/uploads/auto/C%3A/Windows/x.evtx",
      "WS-ALPHA-C.0000000000000001/notes.txt",
      "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json",
      "results/summary.json",
      "other/thing.json",
    ];
    const [p] = planHuntExports(paths);
    expect(p.members.sort()).toEqual([
      "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json",
      "hunt_info.json",
    ]);
  });

  it("finds nothing in an ordinary folder", () => {
    expect(planHuntExports(["a/b.json", "results/All x.json", "chainsaw.json"])).toEqual([]);
  });

  it("plans two sibling hunts separately", () => {
    const paths = [
      ...Object.keys(huntTree("perClientJson", "h1")),
      ...Object.keys(huntTree("huntWide", "h2")),
    ];
    const plans = planHuntExports(paths);
    expect(plans.map((p) => [p.root, p.imports.length]).sort()).toEqual([
      ["h1", 9],
      ["h2", 3],
    ]);
  });

  it("summarises skips by reason", () => {
    expect(huntSkipSummary(plan("full").skips)).toBe(
      "9 CSV twin(s) of an imported JSON, 6 hunt-wide copy(ies) of per-client results, 13 collection metadata file(s)",
    );
  });
});

describe("hunt client-folder host (#2714)", () => {
  it("reads the hostname from <host>-C.<16 hex>", () => {
    expect(clientFolderHost("WS-ALPHA-C.0000000000000001")).toBe("WS-ALPHA");
    expect(clientFolderHost("SRV-CHARLIE.example.test-C.00000000000000AF")).toBe("SRV-CHARLIE.example.test");
    expect(clientFolderHost("WS-ALPHA")).toBeNull();
    expect(clientFolderHost("-bad-C.0000000000000001")).toBe("");
  });

  it("a per-client result's folder wins over asset=<HOST>, on either separator", () => {
    expect(assetHostFromDropRelpath("h/WS-BRAVO-C.0000000000000002/results/a.json")).toBe("WS-BRAVO");
    expect(assetHostFromDropRelpath("asset=OTHER\\WS-BRAVO-C.0000000000000002\\results\\a.json")).toBe(
      "WS-BRAVO",
    );
    expect(assetHostFromDropRelpath("asset=OTHER/h/results/All a.json")).toBe("OTHER");
    expect(assetHostFromDropRelpath("WS-BRAVO-C.0000000000000002/client_info.json")).toBe("");
  });
});

describe("veloArtifactFromLabel — hunt-wide copy (#2714)", () => {
  it("drops the All prefix of a hunt-wide stored name", () => {
    expect(veloArtifactFromLabel("0003_All_Windows.System.Pslist.json")).toBe("Windows.System.Pslist");
    expect(veloArtifactFromLabel("All Windows.System.Pslist.json")).toBe("Windows.System.Pslist");
    expect(veloArtifactFromLabel("0003_Allowed.Things.json")).toBe("Allowed.Things");
  });
});
