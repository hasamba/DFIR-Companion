import { describe, it, expect } from "vitest";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { dedupeIocsById } from "../../src/analysis/iocRepair.js";

describe("dedupeIocsById", () => {
  it("collapses rows sharing the same id, keeping the first occurrence", () => {
    const state = {
      ...emptyState("c1"),
      iocs: [
        { id: "i001", type: "process" as const, value: "OneDrive.exe" },
        { id: "i016", type: "domain" as const, value: "desktop-mnnuhhu.localdomain" },
        { id: "i200", type: "other" as const, value: "C:\\AkiraSim\\" },
        { id: "i016", type: "domain" as const, value: "desktop-mnnuhhu.localdomain" },
        { id: "i201", type: "process" as const, value: "cloudflare.exe" },
        { id: "i016", type: "domain" as const, value: "desktop-mnnuhhu.localdomain" },
      ],
    };
    const { state: repaired, removed } = dedupeIocsById(state);
    expect(removed).toBe(2);
    expect(repaired.iocs).toHaveLength(4);
    expect(repaired.iocs.filter((i) => i.id === "i016")).toHaveLength(1);
    // Order + other entries untouched.
    expect(repaired.iocs.map((i) => i.id)).toEqual(["i001", "i016", "i200", "i201"]);
  });

  it("is a no-op (returns the same state instance) when there are no duplicates", () => {
    const state = {
      ...emptyState("c1"),
      iocs: [
        { id: "i001", type: "ip" as const, value: "10.0.0.5" },
        { id: "i002", type: "domain" as const, value: "evil.example" },
      ],
    };
    const { state: repaired, removed } = dedupeIocsById(state);
    expect(removed).toBe(0);
    expect(repaired).toBe(state);
  });
});
