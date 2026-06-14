import { describe, it, expect } from "vitest";
import {
  SHADOW_ARTIFACTS,
  SHADOW_ARTIFACT_IDS,
  shadowArtifactById,
  gapAffectedAssets,
  shadowArtifactsForGap,
} from "../../src/analysis/shadowArtifacts.js";
import type { TimelineGap } from "../../src/analysis/gapDetect.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, asset?: string): ForensicEvent {
  return { id, timestamp: "2026-05-20T08:00:00Z", description: "", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset };
}

function gap(over: Partial<TimelineGap> = {}): TimelineGap {
  return {
    id: "gap-1",
    startTimestamp: "2026-05-20T08:09:00.000Z",
    endTimestamp: "2026-05-20T10:09:00.000Z",
    durationSeconds: 7200,
    durationLabel: "2h",
    severity: "High",
    complete: true,
    silentSources: ["EventLog"],
    activeSources: [],
    beforeEventId: "a9",
    afterEventId: "b0",
    ...over,
  };
}

describe("SHADOW_ARTIFACTS catalog", () => {
  it("is non-empty and covers the artifacts the issue names", () => {
    expect(SHADOW_ARTIFACTS.length).toBeGreaterThan(0);
    const ids = new Set(SHADOW_ARTIFACTS.map((a) => a.id));
    for (const id of ["usn-journal", "srum", "prefetch", "amcache"]) expect(ids.has(id)).toBe(true);
  });

  it("has unique ids that match SHADOW_ARTIFACT_IDS", () => {
    const ids = SHADOW_ARTIFACTS.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length); // no dupes
    expect(SHADOW_ARTIFACT_IDS).toEqual(new Set(ids));
  });

  it("every entry has a deployable VQL referencing a Velociraptor artifact, on Windows", () => {
    for (const a of SHADOW_ARTIFACTS) {
      expect(a.vql).toMatch(/^SELECT .+ FROM Artifact\./);
      expect(a.vql).toContain(a.velociraptorArtifact);
      expect(a.categories.length).toBeGreaterThan(0);
      expect(a.os).toBe("windows");
      expect(a.reconstructs.trim().length).toBeGreaterThan(0);
      expect(a.whyResilient.trim().length).toBeGreaterThan(0);
    }
  });
});

describe("shadowArtifactById", () => {
  it("resolves a known id (case-insensitively) and returns undefined for an unknown id", () => {
    expect(shadowArtifactById("prefetch")?.name).toContain("Prefetch");
    expect(shadowArtifactById("  PREFETCH ")?.id).toBe("prefetch");
    expect(shadowArtifactById("nope")).toBeUndefined();
  });
});

describe("gapAffectedAssets", () => {
  it("dedupes, sorts, and ignores blank assets", () => {
    const hosts = gapAffectedAssets([ev("e1", "WEB01"), ev("e2", "DC01"), ev("e3", "WEB01"), ev("e4", "  "), ev("e5")]);
    expect(hosts).toEqual(["DC01", "WEB01"]);
  });

  it("caps the host list", () => {
    const many = Array.from({ length: 20 }, (_, i) => ev(`e${i}`, `H${String(i).padStart(2, "0")}`));
    expect(gapAffectedAssets(many, 3)).toHaveLength(3);
  });

  it("returns [] when nothing names an asset", () => {
    expect(gapAffectedAssets([ev("e1"), ev("e2")])).toEqual([]);
  });
});

describe("shadowArtifactsForGap", () => {
  it("returns the full catalog plus the hosts derived from the surrounding events", () => {
    const result = shadowArtifactsForGap(gap(), [ev("a9", "WEB01"), ev("b0", "DC01")]);
    expect(result.artifacts).toEqual(SHADOW_ARTIFACTS);
    expect(result.targetHosts).toEqual(["DC01", "WEB01"]);
  });

  it("offers the collections even when no host is identifiable", () => {
    const result = shadowArtifactsForGap(gap(), [ev("a9"), ev("b0")]);
    expect(result.targetHosts).toEqual([]);
    expect(result.artifacts.length).toBe(SHADOW_ARTIFACTS.length);
  });
});
