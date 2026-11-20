import { describe, it, expect } from "vitest";
import {
  artifactRowHold,
  huntArtifactLimitsFromEnv,
  planHolds,
  clientFolderOf,
} from "../../src/analysis/huntArtifactLimits.js";

// #2746: which hunt result files are over the size limits. Synthetic paths only.

const MB = 1024 * 1024;
const file = (client: string, artifact: string, mb: number, huntWide = false) => ({
  path: huntWide
    ? `results/All ${artifact}.json`
    : `${client}-C.000000000000000${client.length}/results/${artifact}.json`,
  artifact,
  huntWide,
  bytes: mb * MB,
});

describe("hunt artifact size limits (#2746)", () => {
  it("defaults to 50 MB per PC and 200 MB across PCs; 0 is off; junk falls back", () => {
    expect(huntArtifactLimitsFromEnv({})).toEqual({ hostMb: 50, totalMb: 200 });
    expect(
      huntArtifactLimitsFromEnv({
        DFIR_HUNT_ARTIFACT_HOST_MAX_MB: "0",
        DFIR_HUNT_ARTIFACT_TOTAL_MAX_MB: "x",
      }),
    ).toEqual({ hostMb: 0, totalMb: 200 });
    expect(huntArtifactLimitsFromEnv({ DFIR_HUNT_ARTIFACT_HOST_MAX_MB: "-3" }).hostMb).toBe(50);
  });

  it("holds one PC's artifact over the per-PC limit, not its other artifacts or PCs", () => {
    const held = planHolds(
      [file("WS-A", "Hayabusa", 60), file("WS-A", "Pslist", 5), file("WS-B", "Hayabusa", 10)],
      { hostMb: 50, totalMb: 200 },
    );
    expect(held).toHaveLength(1);
    expect(held[0]).toMatchObject({ artifact: "Hayabusa", reason: "host", limitMb: 50, groupBytes: 60 * MB });
  });

  it("holds an artifact for every PC when its sum crosses the across-PCs limit", () => {
    const held = planHolds(
      [file("WS-A", "Hayabusa", 45), file("WS-B", "Hayabusa", 45), file("WS-C", "Hayabusa", 45)],
      { hostMb: 50, totalMb: 100 },
    );
    expect(held).toHaveLength(3);
    expect(held.every((h) => h.reason === "total" && h.groupBytes === 135 * MB)).toBe(true);
  });

  it("a hunt-wide copy has no per-PC limit, only the across-PCs one", () => {
    expect(planHolds([file("", "Hayabusa", 120, true)], { hostMb: 50, totalMb: 200 })).toEqual([]);
    const held = planHolds([file("", "Hayabusa", 250, true)], { hostMb: 50, totalMb: 200 });
    expect(held).toEqual([expect.objectContaining({ reason: "total", host: "" })]);
  });

  it("0 turns each limit off", () => {
    const big = [file("WS-A", "Hayabusa", 900)];
    expect(planHolds(big, { hostMb: 0, totalMb: 0 })).toEqual([]);
    expect(planHolds(big, { hostMb: 0, totalMb: 200 })[0].reason).toBe("total");
    expect(planHolds(big, { hostMb: 50, totalMb: 0 })[0].reason).toBe("host");
  });

  it("names the client folder a result sits in", () => {
    expect(clientFolderOf("hunt/WS-A-C.1/results/X.json")).toBe("WS-A-C.1");
    expect(clientFolderOf("results/All X.json")).toBe("");
  });
});

describe("bundle hunt artifact holds (#2753)", () => {
  const row = (client: string, pad: number) => ({
    ClientId: client,
    Fqdn: `${client}.example.test`,
    Pad: "x".repeat(pad),
  });

  it("holds the artifact when one PC's rows pass the per-PC limit, naming that PC", () => {
    const rows = [row("C.1", 3000), row("C.2", 100)];
    const h = artifactRowHold("Pstree", rows, { hostMb: 2000 / 1048576, totalMb: 0 });
    expect(h).toMatchObject({ artifact: "Pstree", reason: "host", hosts: ["C.1.example.test"] });
  });

  it("holds it as a whole past the across-PCs limit", () => {
    const rows = [row("C.1", 900), row("C.2", 900)];
    expect(artifactRowHold("Pstree", rows, { hostMb: 0, totalMb: 1500 / 1048576 })).toMatchObject({
      reason: "total",
      hosts: [],
    });
  });

  it("counts UTF-8 bytes, and rows with no ClientId toward the total only", () => {
    const multi = { Pad: "é".repeat(600) }; // 1200 UTF-8 bytes, 600 UTF-16 units
    expect(artifactRowHold("A", [multi], { hostMb: 0, totalMb: 1000 / 1048576 })?.reason).toBe("total");
    expect(artifactRowHold("A", [multi, multi], { hostMb: 1000 / 1048576, totalMb: 0 })).toBeUndefined();
  });

  it("returns nothing under both limits or with both off", () => {
    expect(artifactRowHold("A", [row("C.1", 10)], { hostMb: 50, totalMb: 200 })).toBeUndefined();
    expect(artifactRowHold("A", [row("C.1", 99999)], { hostMb: 0, totalMb: 0 })).toBeUndefined();
  });
});
