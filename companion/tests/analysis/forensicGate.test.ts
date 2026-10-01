import { describe, it, expect } from "vitest";
import {
  SEVERITY_RANK,
  demoteBelowSeverity,
  resolveForensicMinSeverity,
} from "../../src/analysis/forensicGate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, severity: ForensicEvent["severity"]): ForensicEvent {
  return {
    id,
    timestamp: "2026-06-01T00:00:00Z",
    description: id,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

describe("SEVERITY_RANK", () => {
  it("orders Info lowest through Critical highest", () => {
    expect(SEVERITY_RANK.Info).toBeLessThan(SEVERITY_RANK.Low);
    expect(SEVERITY_RANK.Low).toBeLessThan(SEVERITY_RANK.Critical);
  });
});

describe("demoteBelowSeverity", () => {
  const events = [ev("info", "Info"), ev("low", "Low"), ev("high", "High")];
  it("with min=Low keeps Low+ and demotes Info", () => {
    const { kept, demoted } = demoteBelowSeverity(events, "Low");
    expect(kept.map((e) => e.id)).toEqual(["low", "high"]);
    expect(demoted.map((e) => e.id)).toEqual(["info"]);
  });
  it("with min=Info keeps everything (old behavior)", () => {
    const { kept, demoted } = demoteBelowSeverity(events, "Info");
    expect(kept).toHaveLength(3);
    expect(demoted).toHaveLength(0);
  });
  it("with min=Medium demotes Info and Low", () => {
    const { demoted } = demoteBelowSeverity(events, "Medium");
    expect(demoted.map((e) => e.id).sort()).toEqual(["info", "low"]);
  });
});

// #1919: an analyst-entered manual event stays at any severity, like a promoted row. The exemption
// is the manual- id only the manual-entry builders mint, so imported Info telemetry is still cut.
describe("demoteBelowSeverity — manual events (#1919)", () => {
  it("keeps a manual Info event and still demotes an imported Info row", () => {
    const { kept, demoted } = demoteBelowSeverity([ev("manual-abc", "Info"), ev("imported", "Info")], "Low");
    expect(kept.map((e) => e.id)).toEqual(["manual-abc"]);
    expect(demoted.map((e) => e.id)).toEqual(["imported"]);
  });
  it("keeps a manual Low event under a Medium floor", () => {
    const { demoted } = demoteBelowSeverity([ev("manual-xyz", "Low"), ev("row", "Low")], "Medium");
    expect(demoted.map((e) => e.id)).toEqual(["row"]);
  });
  it("does not exempt an imported row whose sources merely say 'manual'", () => {
    const { demoted } = demoteBelowSeverity([{ ...ev("ai-row", "Info"), sources: ["manual"] }], "Low");
    expect(demoted.map((e) => e.id)).toEqual(["ai-row"]);
  });
});

describe("resolveForensicMinSeverity", () => {
  it("prefers the per-case value", () => {
    expect(resolveForensicMinSeverity("Medium", "Low")).toBe("Medium");
  });
  it("falls back to the env value when no per-case value", () => {
    expect(resolveForensicMinSeverity(undefined, "Info")).toBe("Info");
  });
  it("defaults to Low when neither is set or env is invalid", () => {
    expect(resolveForensicMinSeverity(undefined, undefined)).toBe("Low");
    expect(resolveForensicMinSeverity(undefined, "banana")).toBe("Low");
  });
});
