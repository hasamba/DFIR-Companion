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
  it("#2810: per-client + hunt-wide + CSV: imports only the hunt-wide JSON, one per artifact", () => {
    const p = plan("full", "Hunt1");
    expect(p.root).toBe("Hunt1");
    expect(p.imports).toHaveLength(3);
    expect(p.imports.every((i) => i.huntWide && i.path.endsWith(".json"))).toBe(true);
    const reasons = Object.fromEntries(p.skips.map((s) => [s.path, s.reason]));
    expect(reasons["Hunt1/hunt_info.json"]).toBe("metadata");
    expect(reasons["Hunt1/WS-ALPHA-C.0000000000000001/client_info.json"]).toBe("metadata");
    expect(reasons["Hunt1/WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.csv"]).toBe("csv-twin");
    expect(reasons["Hunt1/WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json"]).toBe(
      "per-client-copy",
    );
    expect(reasons["Hunt1/results/All Windows.System.Pslist.csv"]).toBe("csv-twin");
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

  it("#2810: CSV only for one artifact: the hunt-wide CSV imports, its per-client CSVs are skipped", () => {
    const p = plan("csvOnlyUsers");
    const users = p.imports.filter((i) => i.artifact === "Windows.Sys.Users%2FUsers");
    expect(users).toEqual([
      {
        path: "results/All Windows.Sys.Users%2FUsers.csv",
        artifact: "Windows.Sys.Users%2FUsers",
        huntWide: true,
      },
    ]);
    expect(
      p.skips.filter((s) => s.reason === "per-client-copy" && s.path.endsWith("Users.csv")),
    ).toHaveLength(3);
  });

  it("#2810: an artifact whose per-client files a run already started stays per-client", () => {
    const paths = Object.keys(huntTree("full"));
    const started = new Set(["WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json"]);
    const [p] = planHuntExports(paths, started);
    const pslist = p.imports.filter((i) => i.artifact === "Windows.System.Pslist");
    expect(pslist).toHaveLength(3);
    expect(pslist.every((i) => !i.huntWide)).toBe(true);
    expect(p.skips).toContainEqual({
      path: "results/All Windows.System.Pslist.json",
      reason: "hunt-wide-copy",
    });
    const others = p.imports.filter((i) => i.artifact !== "Windows.System.Pslist");
    expect(others.every((i) => i.huntWide)).toBe(true);
  });

  it("per-client JSON beats a hunt-wide CSV of the same artifact", () => {
    const [p] = planHuntExports([
      "hunt_info.json",
      "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json",
      "results/All Windows.System.Pslist.csv",
    ]);
    expect(p.imports.map((i) => i.path)).toEqual([
      "WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json",
    ]);
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
      "12 CSV twin(s) of an imported JSON, 9 per-client copy(ies) of an imported hunt-wide result, 13 collection metadata file(s)",
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
