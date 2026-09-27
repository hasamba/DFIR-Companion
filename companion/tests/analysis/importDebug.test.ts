import { describe, it, expect } from "vitest";
import {
  createImportDebugRecorder,
  formatImportDebugLine,
  sanitizeImportDebugSummary,
  safeKind,
} from "../../src/analysis/importDebug.js";

// #1736: the recorder is the privacy boundary for importer debug detail — the support bundle does
// not run it through the text redactor. Every assertion here is about what may NOT get through.

describe("import debug recorder", () => {
  it("keeps allowlisted column names and replaces anything else with <unlisted>", () => {
    const r = createImportDebugRecorder();
    r.field("timestamp", "TimeCreated");
    r.field("timestamp", "TimeCreated");
    r.field("host", "WKS-FIN-07"); // a value, not a column name
    r.field("user", "Alice Cohen");
    const s = r.summary();
    expect(s.fields.timestamp).toEqual({ TimeCreated: 2 });
    expect(s.fields.host).toEqual({ "<unlisted>": 1 });
    expect(JSON.stringify(s)).not.toContain("WKS-FIN-07");
    expect(JSON.stringify(s)).not.toContain("Alice");
  });

  it("ignores a target outside the closed list", () => {
    const r = createImportDebugRecorder();
    r.field("client_codename" as never, "EventID");
    expect(Object.keys(r.summary().fields)).toEqual([]);
  });

  it("turns any non-slug reason into `other`", () => {
    const r = createImportDebugRecorder();
    r.skipped("missing_timestamp", 3);
    r.skipped("Row 7: Alice Cohen");
    r.observed("host WKS-FIN-07");
    r.fallback("__proto__");
    const s = r.summary();
    expect(s.skipped).toEqual({ missing_timestamp: 3, other: 1 });
    expect(s.observations).toEqual({ other: 1 });
    expect(s.fallbacks).toEqual({ other: 1 });
  });

  it("records a custom importer's id as `custom`", () => {
    expect(safeKind("acme-project-falcon-importer")).toBe("custom");
    expect(safeKind("siem")).toBe("siem");
    const r = createImportDebugRecorder();
    r.detected("acme-project-falcon-importer", { confident: true, decision: "custom_first" });
    expect(r.summary().kind).toBe("custom");
    expect(JSON.stringify(r.summary())).not.toContain("falcon");
  });

  it("keeps a known detection decision", () => {
    const r = createImportDebugRecorder();
    r.detected("siem", { confident: false, decision: "builtin_unconfident" });
    r.detected("siem"); // a later call without a decision keeps the resolver's
    expect(r.summary().detection).toEqual({ confident: false, decision: "builtin_unconfident" });
  });

  it("rejects negative, fractional and unsafe counts, and saturates", () => {
    const r = createImportDebugRecorder();
    r.counts({ total: -5, kept: 2.9, dropped: Number.POSITIVE_INFINITY });
    r.skipped("bad_row", Number.MAX_SAFE_INTEGER);
    r.skipped("bad_row", 10);
    const s = r.summary();
    expect(s.counts).toEqual({ kept: 2 });
    expect(s.skipped.bad_row).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("caps each map and says the detail is partial", () => {
    const r = createImportDebugRecorder();
    for (let i = 0; i < 40; i++) r.skipped(`reason_${i}`);
    const s = r.summary();
    expect(Object.keys(s.skipped).length).toBe(32);
    expect(s.truncated).toBe(true);
  });

  it("records a failure location only as a known phase and a row number", () => {
    const r = createImportDebugRecorder();
    r.failedAt("parse", 42);
    expect(r.summary().failure).toEqual({ phase: "parse", row: 42 });
    r.failedAt("Alice's phase", -1);
    expect(r.summary().failure).toEqual({ phase: "other" });
  });

  it("stores a __proto__ key as data, not as a prototype", () => {
    const r = createImportDebugRecorder();
    r.field("host", "__proto__");
    const s = r.summary();
    expect(Object.getPrototypeOf(s.fields.host)).toBeNull();
  });

  it("formats one line with no file name, only the kind and the summary", () => {
    const r = createImportDebugRecorder();
    r.detected("csv");
    r.finish("failed");
    const line = formatImportDebugLine(r.summary());
    expect(line.startsWith("[import-debug] importer csv: {")).toBe(true);
    expect(line).toContain('"outcome":"failed"');
  });
});

describe("sanitizeImportDebugSummary", () => {
  it("strips anything a hand-built summary tries to smuggle", () => {
    const dirty = {
      kind: "acme-codename",
      detection: { confident: "yes", decision: "Alice picked it" },
      counts: { total: 10, kept: -1, secret: 5 },
      fields: { host: { "WKS-FIN-07": 3, Computer: 2 }, codename: { EventID: 1 } },
      skipped: { missing_timestamp: 2, "Alice Cohen": 1 },
      omitted: {},
      observations: {},
      fallbacks: { generic_mapper: 4 },
      failure: { phase: "parse", row: 3.5 },
      outcome: "exploded",
      truncated: "no",
      extra: "WKS-FIN-07",
    };
    const s = sanitizeImportDebugSummary(dirty)!;
    const json = JSON.stringify(s);
    for (const bad of ["acme", "Alice", "WKS-FIN-07", "codename", "secret", "exploded", "extra"])
      expect(json).not.toContain(bad);
    expect(s.kind).toBe("custom");
    expect(s.fields.host).toEqual({ Computer: 2 });
    expect(s.counts).toEqual({ total: 10 });
    expect(s.failure).toEqual({ phase: "parse", row: 3 });
    expect(s.truncated).toBe(false);
  });

  it("returns undefined for a non-object", () => {
    expect(sanitizeImportDebugSummary("x")).toBeUndefined();
    expect(sanitizeImportDebugSummary(null)).toBeUndefined();
  });
});
