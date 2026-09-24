import { describe, it, expect } from "vitest";
import {
  buildCollectionInventory,
  coveredOnAll,
  inventorySignature,
  renderCollectionInventory,
} from "../../src/analysis/collectionInventory.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";

// #1588 — the collection inventory is what the model judges every "not observed" answer against, so
// it must be deterministic and must never call a detection feed "collection". Built on the
// INC-2026-005 shape: Sigma/Chainsaw hits on Sysmon, no raw Sysmon, a cleared Security log.

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-08-28T09:00:00Z",
    description: `event ${id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    ...over,
  };
}

const CHAINSAW = (id: string): ForensicEvent =>
  ev(id, { sources: ["Chainsaw"], description: "Sigma: Suspicious file write" });
const PREFETCH = ev("p1", { sources: ["Velociraptor"], artifactName: "Windows.Forensics.Prefetch" });
const CLEAR = (id: string, at: string, host = "WS01"): ForensicEvent =>
  ev(id, {
    timestamp: at,
    asset: host,
    description: "Security audit log cleared (EID 1102)",
    sources: ["Velociraptor"],
  });

function job(over: Partial<VeloHuntJob>): VeloHuntJob {
  return {
    bundleId: "b",
    bundleName: "B",
    artifacts: [],
    huntId: "H.1",
    launchedAt: "2026-08-28T10:00:00Z",
    waitMinutes: 5,
    collectAt: "2026-08-28T10:05:00Z",
    status: "imported",
    ...over,
  };
}

describe("collection inventory (#1588)", () => {
  it("a detection feed built on Sysmon is not file-activity collection", () => {
    const inv = buildCollectionInventory({ events: [CHAINSAW("c1"), CHAINSAW("c2"), PREFETCH] });
    expect(coveredOnAll(inv, ["WS01"])).toEqual(new Set(["execution"]));
    const text = renderCollectionInventory(inv);
    expect(text).toContain(
      "- WS01: collected raw: execution; no raw collection found: file-activity, network, persistence",
    );
    expect(text).toContain(
      "file-activity → Windows.EventLogs.Evtx (Microsoft-Windows-Sysmon/Operational EID 11/23",
    );
    expect(text).toContain("Chainsaw (detections) 2");
    expect(text).toContain("Windows.Forensics.Prefetch (raw) 1");
  });

  it("raw Sysmon collected through Windows.EventLogs.Evtx covers the class its record type names", () => {
    const sysmonFile = ev("s1", {
      sources: ["Velociraptor"],
      artifactName: "Windows.EventLogs.Evtx",
      sourceRecordId: "evtx:microsoft-windows-sysmon/operational:42",
      canonical: { event: { category: "file", type: "creation" } } as ForensicEvent["canonical"],
    });
    expect(
      coveredOnAll(buildCollectionInventory({ events: [sysmonFile] }), ["WS01"]).has("file-activity"),
    ).toBe(true);
    // A rule hit on the SAME record is still a detection feed.
    const hit = { ...sysmonFile, id: "s2", sources: ["Hayabusa"], artifactName: undefined };
    expect(coveredOnAll(buildCollectionInventory({ events: [hit] }), ["WS01"]).has("file-activity")).toBe(
      false,
    );
  });

  it("coverage is per host: WS01's collection says nothing about WS02", () => {
    const inv = buildCollectionInventory({
      events: [PREFETCH, ev("w2", { asset: "WS02", sources: ["Chainsaw"] })],
    });
    expect(coveredOnAll(inv, ["WS01"]).has("execution")).toBe(true);
    expect(coveredOnAll(inv, ["WS02"]).has("execution")).toBe(false);
    expect(coveredOnAll(inv, ["WS01", "WS02"]).has("execution")).toBe(false);
  });

  it("a log clear is recorded per host and channel with its LATEST time; wevtutil running is not a clear", () => {
    const wevtutil = ev("x", {
      description: "Prefetch: WEVTUTIL.EXE executed",
      mitreTechniques: ["T1070.001"],
      artifactName: "Windows.Forensics.Prefetch",
    });
    const inv = buildCollectionInventory({
      events: [CLEAR("k1", "2026-08-28T09:10:00Z"), CLEAR("k2", "2026-08-28T09:12:03Z"), wevtutil],
    });
    expect(inv.cleared).toEqual([
      { host: "WS01", channel: "Security", at: "2026-08-28T09:12:03Z", count: 2 },
    ]);
    expect(renderCollectionInventory(inv)).toContain(
      "- Cleared: Security log on WS01 at 2026-08-28T09:12:03Z (cleared 2×; latest shown)",
    );
  });

  it("names the channel a System 104 row says was cleared, and admits when it does not say", () => {
    const named = ev("n", { description: "Event log cleared: The Windows PowerShell log file was cleared." });
    const bare = ev("b", { description: "Event log cleared", asset: "WS02" });
    const inv = buildCollectionInventory({ events: [named, bare] });
    expect(inv.cleared.map((c) => `${c.host}:${c.channel}`)).toEqual(["WS01:Windows PowerShell", "WS02:"]);
    expect(renderCollectionInventory(inv)).toContain("An event log (channel not recorded) on WS02");
  });

  it("reads imported hunt metadata only: empty, failed, truncated, archive-only, still running", () => {
    const inv = buildCollectionInventory({
      events: [PREFETCH],
      hunts: [
        job({
          huntId: "H.1",
          artifacts: [
            "Windows.Forensics.Prefetch",
            "Windows.EventLogs.Evtx",
            "Windows.NTFS.MFT",
            "Windows.Search.FileFinder",
            "Custom.X",
          ],
          emptyArtifacts: ["Windows.Search.FileFinder"],
          skippedArtifacts: [{ name: "Windows.NTFS.MFT", error: "timeout" }],
          truncatedArtifacts: [{ name: "Custom.X", kept: 500, total: 501 }],
        }),
        job({ huntId: "H.2", status: "running", artifacts: ["Windows.System.TaskScheduler"] }),
        job({ huntId: "H.3", status: "error", artifacts: ["Windows.Sysinternals.Autoruns"] }),
      ],
    });
    expect(inv.hunts.map((h) => `${h.artifact}=${h.state}`)).toEqual([
      "Custom.X=truncated",
      "Windows.EventLogs.Evtx=archive-only",
      "Windows.NTFS.MFT=failed",
      "Windows.Search.FileFinder=empty",
      "Windows.System.TaskScheduler=running",
    ]);
  });

  it("is deterministic: input order does not change the text", () => {
    const events = [
      CHAINSAW("c1"),
      PREFETCH,
      CLEAR("k1", "2026-08-28T09:12:03Z"),
      ev("w2", { asset: "WS02" }),
    ];
    const a = renderCollectionInventory(buildCollectionInventory({ events }));
    const b = renderCollectionInventory(buildCollectionInventory({ events: [...events].reverse() }));
    expect(a).toBe(b);
    expect(a).toContain("Rules for negative answers:");
  });

  it("the hunt signature changes when a hunt's outcome changes, and not with list order", () => {
    const one = job({ huntId: "H.1", artifacts: ["A"] });
    const two = job({ huntId: "H.2", artifacts: ["B"] });
    expect(inventorySignature([one, two])).toBe(inventorySignature([two, one]));
    expect(inventorySignature([one])).not.toBe(inventorySignature([{ ...one, emptyArtifacts: ["A"] }]));
  });

  it("renders nothing for an empty case", () => {
    expect(renderCollectionInventory(buildCollectionInventory({ events: [] }))).toBe("");
  });
});
