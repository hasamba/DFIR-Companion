import { describe, it, expect } from "vitest";
import { applySeverityFloor, hasGradedSeverity, parseMinSeverity, SEVERITY_RANK } from "../../src/analysis/severityFloor.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

// Build a list of events carrying just a severity (all the floor needs).
const ev = (...sevs: Severity[]): { severity: Severity; id: string }[] =>
  sevs.map((severity, i) => ({ severity, id: `e${i}` }));
const sevs = (list: { severity: Severity }[]): Severity[] => list.map((e) => e.severity);

describe("severityFloor — gate-aware import floor", () => {
  it("ranks Critical highest and Info lowest", () => {
    expect(SEVERITY_RANK.Critical).toBeLessThan(SEVERITY_RANK.High);
    expect(SEVERITY_RANK.Low).toBeLessThan(SEVERITY_RANK.Info);
  });

  it("treats any above-Info event as graded, all-Info / empty as ungraded", () => {
    expect(hasGradedSeverity(ev("Info", "Info"))).toBe(false);
    expect(hasGradedSeverity([])).toBe(false);
    expect(hasGradedSeverity(ev("Info", "Low"))).toBe(true);
    expect(hasGradedSeverity(ev("Critical"))).toBe(true);
  });

  it("no floor / Info floor → imports everything (Info is the lowest rung)", () => {
    const list = ev("Critical", "Medium", "Info");
    expect(applySeverityFloor(list, undefined)).toBe(list);            // unchanged reference
    expect(sevs(applySeverityFloor(list, "Info"))).toEqual(["Critical", "Medium", "Info"]);
  });

  it("graded import → keeps only events at or above the floor (drops Info + below)", () => {
    const list = ev("Critical", "High", "Medium", "Low", "Info");
    expect(sevs(applySeverityFloor(list, "Medium"))).toEqual(["Critical", "High", "Medium"]);
    expect(sevs(applySeverityFloor(list, "High"))).toEqual(["Critical", "High"]);
    expect(sevs(applySeverityFloor(list, "Critical"))).toEqual(["Critical"]);
    // "low" keeps everything except Info.
    expect(sevs(applySeverityFloor(list, "Low"))).toEqual(["Critical", "High", "Medium", "Low"]);
  });

  it("ungraded import (all Info) → imports everything REGARDLESS of the floor (the core rule)", () => {
    const telemetry = ev("Info", "Info", "Info"); // e.g. KAPE / Plaso super-timeline
    expect(applySeverityFloor(telemetry, "High")).toBe(telemetry);     // unchanged reference
    expect(sevs(applySeverityFloor(telemetry, "Critical"))).toEqual(["Info", "Info", "Info"]);
  });

  it("mixed import (detections + Info telemetry) → floor applies and drops the Info noise", () => {
    const mixed = ev("High", "Info", "Info"); // e.g. Velociraptor Sigma hit + EventLog rows
    expect(sevs(applySeverityFloor(mixed, "High"))).toEqual(["High"]);
  });

  it("a graded import with nothing above the floor → empties (user asked for higher than exists)", () => {
    expect(applySeverityFloor(ev("Medium", "Low"), "High")).toHaveLength(0);
  });

  it("does not mutate the input array", () => {
    const list = ev("Critical", "Info");
    const before = [...list];
    applySeverityFloor(list, "High");
    expect(list).toEqual(before);
  });

  it("parseMinSeverity normalizes free-form input; unrecognized → undefined (import everything)", () => {
    expect(parseMinSeverity("HIGH")).toBe("High");
    expect(parseMinSeverity("  medium ")).toBe("Medium");
    expect(parseMinSeverity("info")).toBe("Info");
    expect(parseMinSeverity("")).toBeUndefined();
    expect(parseMinSeverity("bogus")).toBeUndefined();
    expect(parseMinSeverity(undefined)).toBeUndefined();
  });
});
