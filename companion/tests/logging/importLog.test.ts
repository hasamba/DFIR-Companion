import { describe, it, expect } from "vitest";
import {
  createImportProgressThrottle,
  describeMb,
  formatImportCancelled,
  formatImportFailed,
  IMPORT_PROGRESS_DETAIL,
  sanitizeLabel,
  formatImportMerged,
  formatImportSettled,
  formatImportStart,
} from "../../src/logging/importLog.js";

// The import log lines (#1438): stable, greppable, one prefix. These pin the wording the seams
// emit so a change shows up here, not in a session log an analyst is reading at 3 a.m.

describe("import log formatters", () => {
  it("describes sizes with one decimal under 10 MB and whole MB above", () => {
    expect(describeMb(512 * 1024)).toBe("0.5 MB");
    expect(describeMb(9.96 * 1024 * 1024)).toBe("10.0 MB");
    expect(describeMb(108_646_243)).toBe("104 MB");
  });

  it("formats the start line with bytes, lines, or neither", () => {
    expect(
      formatImportStart({ caseId: "c1", label: "0018_x.json", kind: "velociraptor", bytes: 108_646_243 }),
    ).toBe("[import] c1 0018_x.json: start — velociraptor, 104 MB");
    expect(formatImportStart({ caseId: "c1", label: "0003_t.jsonl", kind: "thor", lines: 1200 })).toBe(
      "[import] c1 0003_t.jsonl: start — thor, 1200 line(s)",
    );
    expect(formatImportStart({ caseId: "c1", label: "f.json", kind: "velociraptor", bytes: 10 })).toBe(
      "[import] c1 f.json: start — velociraptor, 0.0 MB",
    );
  });

  it("formats merged, settled and failed lines", () => {
    expect(formatImportMerged("c1", "0018_x.json", 12_345)).toBe(
      "[import] c1 0018_x.json: parsed and merged in 12 s",
    );
    expect(formatImportMerged("c1", "0018_x.json", 900)).toBe(
      "[import] c1 0018_x.json: parsed and merged in 0.9 s",
    );
    expect(
      formatImportSettled({
        caseId: "c1",
        label: "0018_x.json",
        forensicAdded: 3,
        forensicRemoved: 0,
        superAdded: 800,
        iocsAdded: 5,
        elapsedMs: 31_000,
      }),
    ).toBe("[import] c1 0018_x.json: done — forensic +3, super +800, IOCs +5 (31 s)");
    expect(
      formatImportSettled({
        caseId: "c1",
        forensicAdded: 0,
        forensicRemoved: 2,
        superAdded: 0,
        iocsAdded: 0,
        iocsRemoved: 1,
      }),
    ).toBe("[import] c1: done — forensic +0/-2, super +0, IOCs +0/-1");
    expect(
      formatImportFailed({
        caseId: "c1",
        label: "0018_x.json",
        kind: "velociraptor",
        message: "Invalid string length",
        elapsedMs: 4000,
      }),
    ).toBe("[import] c1 0018_x.json: FAILED (velociraptor) after 4.0 s — Invalid string length");
  });
});

describe("label hygiene and the progress-detail gate", () => {
  it("strips control characters so a filename cannot forge a log line, and caps the length", () => {
    expect(sanitizeLabel("evil\n2026-09-20T00:00:00Z INFO [req] forged\r.json")).toBe(
      "evil 2026-09-20T00:00:00Z INFO [req] forged .json",
    );
    expect(sanitizeLabel("x".repeat(300))).toHaveLength(201);
    expect(formatImportStart({ caseId: "c1", label: "a\u0000b", kind: "thor" })).toBe(
      "[import] c1 a b: start — thor",
    );
    expect(formatImportFailed({ caseId: "c1", label: "f", kind: "thor", message: "bad\nline" })).toBe(
      "[import] c1 f: FAILED (thor) — bad line",
    );
    // `kind` can carry an MCP tool name from the request body — it is a label too.
    expect(formatImportFailed({ caseId: "c1", label: "f", kind: "mcp:s/x\nforged", message: "m" })).toBe(
      "[import] c1 f: FAILED (mcp:s/x forged) — m",
    );
    expect(formatImportCancelled("c1", "f.json", 2500)).toBe(
      "[import] c1 f.json: cancelled after 2.5 s — stored evidence retained",
    );
  });

  it("admits only the '<kind> import — done/total' progress shape", () => {
    for (const ok of [
      "THOR import — 5000/12000",
      "velociraptor import — committed batch 2/7",
      "csv import — 1/1",
      "CSV import — batch 1/3", // the dedicated AI routes' shape
      "log import — batch 2/3",
    ])
      expect(IMPORT_PROGRESS_DETAIL.test(ok)).toBe(true);
    for (const no of [
      "enriching IOC 3/50",
      "enriching IOCs (VirusTotal) — 3/50",
      "importing (velociraptor) — min severity Low",
      "importing 1234 SIEM event(s)",
      "importing Velociraptor hunt H.1 artifact Windows.NTFS.MFT",
      "3 screenshot(s)",
      'importing email "Re: invoice"',
    ])
      expect(IMPORT_PROGRESS_DETAIL.test(no)).toBe(false);
  });
});

describe("createImportProgressThrottle", () => {
  it("logs the first detail at once, then at most one per interval for the same import", () => {
    let t = 0;
    const th = createImportProgressThrottle({ intervalMs: 10_000, now: () => t });
    expect(th.note("c1", "THOR import — 1/10")).toBe("[import] c1: THOR import — 1/10");
    t = 3000;
    expect(th.note("c1", "THOR import — 2/10")).toBeNull();
    t = 10_000;
    expect(th.note("c1", "THOR import — 5/10")).toBe("[import] c1: THOR import — 5/10");
    t = 12_000;
    expect(th.note("c1", "THOR import — 6/10")).toBeNull();
  });

  it("logs at once when the import's label changes, and per case", () => {
    let t = 0;
    const th = createImportProgressThrottle({ intervalMs: 10_000, now: () => t });
    th.note("c1", "THOR import — 1/10");
    t = 1000;
    expect(th.note("c1", "KAPE import — 1/3")).toBe("[import] c1: KAPE import — 1/3");
    expect(th.note("c2", "THOR import — 1/10")).toBe("[import] c2: THOR import — 1/10");
    expect(th.note("c1", "KAPE import — 2/3")).toBeNull();
  });

  it("clear() forgets the case so the next import logs immediately", () => {
    let t = 0;
    const th = createImportProgressThrottle({ intervalMs: 10_000, now: () => t });
    th.note("c1", "THOR import — 1/10");
    th.clear("c1");
    t = 1;
    expect(th.note("c1", "THOR import — 1/10")).toBe("[import] c1: THOR import — 1/10");
  });

  it("treats a detail without a separator as its own label", () => {
    const th = createImportProgressThrottle({ intervalMs: 10_000, now: () => 0 });
    expect(th.note("c1", "reading Windows events")).toBe("[import] c1: reading Windows events");
    expect(th.note("c1", "reading Windows events")).toBeNull();
  });
});
