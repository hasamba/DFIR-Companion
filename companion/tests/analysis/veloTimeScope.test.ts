import { describe, it, expect } from "vitest";
import { resolveTimeScope, buildTimeScopePlan } from "../../src/analysis/veloTimeScope.js";

const NOW = new Date("2026-07-21T12:00:00.000Z");

describe("resolveTimeScope", () => {
  it("returns undefined for no scope, an empty object, and the explicit 'all' preset", () => {
    expect(resolveTimeScope(undefined, NOW)).toBeUndefined();
    expect(resolveTimeScope({}, NOW)).toBeUndefined();
    expect(resolveTimeScope({ preset: "all" }, NOW)).toBeUndefined();
  });

  it("resolves each relative preset to an absolute start with NO end bound", () => {
    // No upper bound on purpose: a hunt keeps scheduling on clients that check in later, so pinning
    // end=launch time would silently drop activity between launch and check-in.
    expect(resolveTimeScope({ preset: "24h" }, NOW)).toEqual({ start: "2026-07-20T12:00:00.000Z" });
    expect(resolveTimeScope({ preset: "7d" }, NOW)).toEqual({ start: "2026-07-14T12:00:00.000Z" });
    expect(resolveTimeScope({ preset: "30d" }, NOW)).toEqual({ start: "2026-06-21T12:00:00.000Z" });
    expect(resolveTimeScope({ preset: "90d" }, NOW)).toEqual({ start: "2026-04-22T12:00:00.000Z" });
  });

  it("resolves a custom range to both bounds, normalized to UTC ISO", () => {
    expect(resolveTimeScope({ start: "2026-06-01T00:00:00Z", end: "2026-06-30T23:59:59Z" }, NOW))
      .toEqual({ start: "2026-06-01T00:00:00.000Z", end: "2026-06-30T23:59:59.000Z" });
  });

  it("accepts a custom range with only a start", () => {
    expect(resolveTimeScope({ start: "2026-06-01T00:00:00Z" }, NOW)).toEqual({ start: "2026-06-01T00:00:00.000Z" });
  });

  it("rejects an unparseable bound and an end before its start", () => {
    expect(() => resolveTimeScope({ start: "not-a-date" }, NOW)).toThrow(/start must be a valid date/);
    expect(() => resolveTimeScope({ start: "2026-06-01T00:00:00Z", end: "nope" }, NOW)).toThrow(/end must be a valid date/);
    expect(() => resolveTimeScope({ start: "2026-06-30T00:00:00Z", end: "2026-06-01T00:00:00Z" }, NOW))
      .toThrow(/end must be at or after start/);
    expect(() => resolveTimeScope({ end: "2026-06-01T00:00:00Z" }, NOW)).toThrow(/start is required/);
  });

  it("rejects an unknown preset rather than silently collecting everything", () => {
    expect(() => resolveTimeScope({ preset: "5y" }, NOW)).toThrow(/unknown time-scope preset/);
  });

  it("rejects preset='custom' with no start (prevents silent unbounded collection)", () => {
    expect(() => resolveTimeScope({ preset: "custom" }, NOW)).toThrow(/start is required/);
    expect(() => resolveTimeScope({ preset: "custom", end: "2026-06-30T00:00:00Z" }, NOW)).toThrow(/start is required/);
  });

  it("preset takes precedence over start/end dates when both are supplied", () => {
    // If both preset and custom dates supplied, preset wins, dates ignored
    expect(resolveTimeScope({ preset: "24h", start: "2026-01-01T00:00:00Z", end: "2026-12-31T23:59:59Z" }, NOW))
      .toEqual({ start: "2026-07-20T12:00:00.000Z" });
  });

  it("whitespace-only preset treated as no preset", () => {
    expect(resolveTimeScope({ preset: "   " }, NOW)).toBeUndefined();
    expect(resolveTimeScope({ preset: "\t\n" }, NOW)).toBeUndefined();
  });

  it("accepts end equal to start as a zero-width window", () => {
    expect(resolveTimeScope({ start: "2026-06-15T12:00:00Z", end: "2026-06-15T12:00:00Z" }, NOW))
      .toEqual({ start: "2026-06-15T12:00:00.000Z", end: "2026-06-15T12:00:00.000Z" });
  });
});

const SCOPE = { start: "2026-06-21T00:00:00.000Z", end: "2026-07-21T00:00:00.000Z" };

// Minimal artifact definitions keyed by name, in the shape listClientArtifacts returns.
const defs = [
  { name: "Windows.EventLogs.Evtx", description: "", parameters: [{ name: "DateAfter", type: "timestamp" }, { name: "DateBefore", type: "timestamp" }] },
  { name: "Windows.Forensics.Prefetch", description: "", parameters: [{ name: "dateAfter" }, { name: "dateBefore" }, { name: "executableRegex" }] },
  { name: "Custom.StartOnly", description: "", parameters: [{ name: "StartDate", type: "timestamp" }] },
  { name: "Custom.EndOnly", description: "", parameters: [{ name: "DateBefore", type: "timestamp" }] },
  { name: "Windows.Forensics.Shellbags", description: "", parameters: [{ name: "UserRegex" }] },
  { name: "Custom.PathParams", description: "", parameters: [{ name: "PathFrom" }, { name: "CopyTo" }] },
  { name: "Custom.NoMeta", description: "", parameters: [] },
];

describe("buildTimeScopePlan — detection", () => {
  it("maps DateAfter/DateBefore and case-variant dateAfter/dateBefore", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Windows.EventLogs.Evtx", "Windows.Forensics.Prefetch"], definitions: defs, scope: SCOPE });
    expect(plan.params).toEqual({
      "Windows.EventLogs.Evtx": { DateAfter: SCOPE.start, DateBefore: SCOPE.end },
      "Windows.Forensics.Prefetch": { dateAfter: SCOPE.start, dateBefore: SCOPE.end },
    });
    expect(plan.scoped.map((s) => s.source)).toEqual(["detected", "detected"]);
  });

  it("scopes an artifact that offers only a lower bound", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Custom.StartOnly"], definitions: defs, scope: SCOPE });
    expect(plan.params).toEqual({ "Custom.StartOnly": { StartDate: SCOPE.start } });
    expect(plan.scoped[0].endParam).toBeUndefined();
  });

  it("omits the upper bound entirely when the scope has no end (a relative preset)", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Windows.EventLogs.Evtx"], definitions: defs, scope: { start: SCOPE.start } });
    expect(plan.params).toEqual({ "Windows.EventLogs.Evtx": { DateAfter: SCOPE.start } });
  });

  it("does not claim an end-only artifact is scoped when the window has no end (nothing would actually be filtered)", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Custom.EndOnly"], definitions: defs, scope: { start: SCOPE.start } });
    expect(plan.params).toEqual({});
    expect(plan.unscoped.map((u) => u.artifact)).toEqual(["Custom.EndOnly"]);
    expect(plan.scoped).toEqual([]);
  });

  it("scopes the same end-only artifact normally when the window has both bounds", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Custom.EndOnly"], definitions: defs, scope: SCOPE });
    expect(plan.params).toEqual({ "Custom.EndOnly": { DateBefore: SCOPE.end } });
    expect(plan.scoped.map((s) => s.artifact)).toEqual(["Custom.EndOnly"]);
    expect(plan.unscoped).toEqual([]);
  });

  it("reports artifacts with no date parameter as unscoped rather than skipping them silently", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Windows.Forensics.Shellbags", "Custom.NoMeta"], definitions: defs, scope: SCOPE });
    expect(plan.params).toEqual({});
    expect(plan.unscoped.map((u) => u.artifact)).toEqual(["Windows.Forensics.Shellbags", "Custom.NoMeta"]);
  });

  it("does not mistake PathFrom / CopyTo for date bounds", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Custom.PathParams"], definitions: defs, scope: SCOPE });
    expect(plan.params).toEqual({});
    expect(plan.unscoped.map((u) => u.artifact)).toEqual(["Custom.PathParams"]);
  });

  it("treats an artifact missing from the server catalog as unscoped", () => {
    const plan = buildTimeScopePlan({ artifacts: ["Not.On.This.Server"], definitions: defs, scope: SCOPE });
    expect(plan.unscoped.map((u) => u.artifact)).toEqual(["Not.On.This.Server"]);
  });

  it("flags the plan degraded when NO artifact in the bundle reported any parameter metadata", () => {
    const bare = [{ name: "Windows.NTFS.MFT", description: "", parameters: [] }];
    expect(buildTimeScopePlan({ artifacts: ["Windows.NTFS.MFT"], definitions: bare, scope: SCOPE }).degraded).toBe(true);
    expect(buildTimeScopePlan({ artifacts: ["Windows.EventLogs.Evtx"], definitions: defs, scope: SCOPE }).degraded).toBe(false);
  });
});

describe("buildTimeScopePlan — precedence", () => {
  it("prefers a saved analyst correction over auto-detection", () => {
    const plan = buildTimeScopePlan({
      artifacts: ["Windows.EventLogs.Evtx"], definitions: defs, scope: SCOPE,
      corrections: { "Windows.EventLogs.Evtx": { start: "EarliestTime", end: "LatestTime" } },
    });
    expect(plan.params).toEqual({ "Windows.EventLogs.Evtx": { EarliestTime: SCOPE.start, LatestTime: SCOPE.end } });
    expect(plan.scoped[0].source).toBe("correction");
  });

  it("prefers the shipped correction table over auto-detection, and a saved correction over both", () => {
    const table = { "Windows.EventLogs.Evtx": { start: "ShippedAfter" } };
    const viaTable = buildTimeScopePlan({ artifacts: ["Windows.EventLogs.Evtx"], definitions: defs, scope: SCOPE, builtInCorrections: table });
    expect(viaTable.params).toEqual({ "Windows.EventLogs.Evtx": { ShippedAfter: SCOPE.start } });
    expect(viaTable.scoped[0].source).toBe("builtin");

    const viaSaved = buildTimeScopePlan({
      artifacts: ["Windows.EventLogs.Evtx"], definitions: defs, scope: SCOPE, builtInCorrections: table,
      corrections: { "Windows.EventLogs.Evtx": { start: "SavedAfter" } },
    });
    expect(viaSaved.params).toEqual({ "Windows.EventLogs.Evtx": { SavedAfter: SCOPE.start } });
  });

  it("never overwrites a date parameter the analyst set by hand on the bundle, and flags it manual", () => {
    const plan = buildTimeScopePlan({
      artifacts: ["Windows.EventLogs.Evtx"], definitions: defs, scope: SCOPE,
      bundleParams: { "Windows.EventLogs.Evtx": { DateAfter: "2020-01-01T00:00:00Z" } },
    });
    expect(plan.params["Windows.EventLogs.Evtx"].DateAfter).toBe("2020-01-01T00:00:00Z");   // preserved
    expect(plan.params["Windows.EventLogs.Evtx"].DateBefore).toBe(SCOPE.end);               // still scoped
    expect(plan.scoped[0].manual).toBe(true);
  });

  it("carries through unrelated bundle parameters untouched", () => {
    const plan = buildTimeScopePlan({
      artifacts: ["Windows.EventLogs.Evtx"], definitions: defs, scope: SCOPE,
      bundleParams: { "Windows.Hayabusa.Rules": { RuleLevel: "Critical, High, and Medium" } },
    });
    expect(plan.params["Windows.Hayabusa.Rules"]).toEqual({ RuleLevel: "Critical, High, and Medium" });
  });
});
