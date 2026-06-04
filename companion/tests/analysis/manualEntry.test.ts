import { describe, it, expect } from "vitest";
import { ZodError } from "zod";
import { buildManualEvent, buildManualIoc } from "../../src/analysis/manualEntry.js";

const deps = { now: () => "2026-06-04T00:00:00.000Z", id: () => "ID1" };

describe("buildManualEvent", () => {
  it("builds a forensic event, normalizes the timestamp, parses MITRE from a string, tags provenance", () => {
    const e = buildManualEvent({
      timestamp: "2026-06-04T13:45:00Z", description: "  Suspicious PowerShell  ",
      severity: "High", asset: "DC01", mitreTechniques: "T1059.001, t1003 garbage",
    }, deps);
    expect(e.id).toBe("manual-ID1");
    expect(e.severity).toBe("High");
    expect(e.description).toBe("Suspicious PowerShell");
    expect(e.timestamp).toBe("2026-06-04T13:45:00.000Z");        // normalized to ISO
    expect(e.mitreTechniques).toEqual(["T1059.001", "T1003"]);   // invalid token dropped
    expect(e.asset).toBe("DC01");
    expect(e.sources).toEqual(["manual"]);
    expect(e.relatedFindingIds).toEqual([]);
  });

  it("defaults a bad severity to Medium and keeps an unparseable timestamp verbatim", () => {
    const e = buildManualEvent({ timestamp: "yesterday-ish", description: "x", severity: "Bogus" }, deps);
    expect(e.severity).toBe("Medium");
    expect(e.timestamp).toBe("yesterday-ish");
    expect(e.mitreTechniques).toEqual([]);
  });

  it("rejects an event with no description", () => {
    expect(() => buildManualEvent({ timestamp: "2026-06-04T00:00:00Z", description: "" }, deps)).toThrow(ZodError);
  });
});

describe("buildManualIoc", () => {
  it("builds an IOC with id/firstSeen", () => {
    const i = buildManualIoc({ type: "ip", value: " 8.8.8.8 " }, deps);
    expect(i).toEqual({ id: "manual-ID1", type: "ip", value: "8.8.8.8", firstSeen: "2026-06-04T00:00:00.000Z" });
  });

  it("rejects an unknown type or an empty value", () => {
    expect(() => buildManualIoc({ type: "mystery", value: "x" }, deps)).toThrow(ZodError);
    expect(() => buildManualIoc({ type: "ip", value: "" }, deps)).toThrow(ZodError);
  });
});
