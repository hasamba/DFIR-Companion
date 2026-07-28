import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ClockSkewStore } from "../../src/analysis/clockSkewStore.js";
import type { ClockSkewReport, ClockSkewResult } from "../../src/analysis/clockSkew.js";

function result(hostKey: string, offsetMs: number, anchorCount = 4): ClockSkewResult {
  return {
    host: hostKey.toUpperCase(), hostKey, offsetMs, anchorCount, dispersionMs: 0,
    confidence: "medium", qualified: true, skewed: Math.abs(offsetMs) > 60_000, sources: ["THOR"],
  };
}

function report(results: ClockSkewResult[], anchorGroups = results.length): ClockSkewReport {
  return { results, referenceHost: results[0]?.host ?? "", anchorGroups, groupsExamined: anchorGroups };
}

let cases: CaseStore;
let store: ClockSkewStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-skewstore-"));
  cases = new CaseStore(root);
  store = new ClockSkewStore(cases);
  await mkdir(cases.stateDir("c1"), { recursive: true });
});

describe("ClockSkewStore", () => {
  it("returns empty defaults for a case that has none", async () => {
    expect(await store.load("c1")).toEqual({
      alignEnabled: false, results: [], overrides: {}, detectedAt: "", anchorGroups: 0, referenceHost: "", updatedAt: "",
    });
  });

  it("round-trips a detection", async () => {
    await store.recordDetection("c1", report([result("ws-01", 120_000)]));
    const loaded = await store.load("c1");
    expect(loaded.results).toHaveLength(1);
    expect(loaded.results[0].offsetMs).toBe(120_000);
    expect(loaded.referenceHost).toBe("WS-01");
    expect(loaded.detectedAt).not.toBe("");
  });

  // Detection reads anchors from the pre-merge timeline; a later run over the correlated timeline
  // legitimately sees fewer, and must not overwrite the better measurement.
  it("keeps the better-anchored result when a later run sees less evidence", async () => {
    await store.recordDetection("c1", report([result("ws-01", 120_000, 9)]));
    await store.recordDetection("c1", report([result("ws-01", 5_000, 2)]));
    const loaded = await store.load("c1");
    expect(loaded.results[0].offsetMs).toBe(120_000);
    expect(loaded.results[0].anchorCount).toBe(9);
  });

  it("takes the fresh result when it is at least as well anchored", async () => {
    await store.recordDetection("c1", report([result("ws-01", 120_000, 4)]));
    await store.recordDetection("c1", report([result("ws-01", 90_000, 6)]));
    expect((await store.load("c1")).results[0].offsetMs).toBe(90_000);
  });

  it("a forced recompute replaces everything, including hosts that vanished", async () => {
    await store.recordDetection("c1", report([result("ws-01", 120_000, 9), result("ws-02", 30_000, 9)]));
    await store.recordDetection("c1", report([result("ws-01", 1_000, 3)]), { replace: true });
    const loaded = await store.load("c1");
    expect(loaded.results.map((r) => r.hostKey)).toEqual(["ws-01"]);
    expect(loaded.results[0].offsetMs).toBe(1_000);
  });

  it("merges results from different hosts across runs", async () => {
    await store.recordDetection("c1", report([result("ws-01", 120_000)]));
    await store.recordDetection("c1", report([result("dc01", 0)]));
    expect((await store.load("c1")).results.map((r) => r.hostKey)).toEqual(["dc01", "ws-01"]);
  });

  it("keeps the toggle and overrides across a detection", async () => {
    await store.setAlign("c1", true);
    await store.setOverride("c1", "WS-02.corp.local", -4_000);
    await store.recordDetection("c1", report([result("ws-01", 120_000)]));
    const loaded = await store.load("c1");
    expect(loaded.alignEnabled).toBe(true);
    expect(loaded.overrides).toEqual({ "ws-02": -4_000 });
  });

  it("normalizes override host keys and clears with null", async () => {
    await store.setOverride("c1", "WS-03.corp.local", 7_000);
    expect((await store.load("c1")).overrides).toEqual({ "ws-03": 7_000 });
    await store.setOverride("c1", "ws-03", null);
    expect((await store.load("c1")).overrides).toEqual({});
  });

  it("keeps a 0 override, which pins a clock as correct", async () => {
    await store.setOverride("c1", "ws-04", 0);
    expect((await store.load("c1")).overrides).toEqual({ "ws-04": 0 });
  });

  // A bad offset here would silently shift a real timeline, so anything unparseable is dropped.
  it("drops malformed results and overrides from a hand-edited file", async () => {
    await writeFile(join(cases.stateDir("c1"), "clock-skew.json"), JSON.stringify({
      alignEnabled: "yes",
      results: [
        { hostKey: "ws-01", offsetMs: 5_000, anchorCount: 4, dispersionMs: 0, confidence: "medium", qualified: true, skewed: false, sources: ["THOR"] },
        { hostKey: "", offsetMs: 1 },
        "nonsense",
        { hostKey: "ws-09", offsetMs: "later", confidence: "certain" },
      ],
      overrides: { "ws-02": 1_000, "ws-03": "soon", "": 5 },
    }));
    const loaded = await store.load("c1");
    expect(loaded.alignEnabled).toBe(false);                    // only a real boolean enables it
    expect(loaded.results.map((r) => r.hostKey)).toEqual(["ws-01", "ws-09"]);
    expect(loaded.results[1].offsetMs).toBe(0);                 // unparseable offset → 0, never trusted
    expect(loaded.results[1].confidence).toBe("low");
    expect(loaded.overrides).toEqual({ "ws-02": 1_000 });
  });
});
