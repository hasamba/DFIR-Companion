import { describe, it, expect } from "vitest";
import {
  buildSnapshot,
  parseSnapshot,
  prepareImport,
  sanitizeSnapshotState,
  SNAPSHOT_FORMAT,
  SNAPSHOT_VERSION,
  SNAPSHOT_STATE_FILES,
  SNAPSHOT_EXCLUDED_STATE_FILES,
} from "../../src/analysis/snapshot.js";

const META = { caseId: "INC-1", name: "Case One", createdAt: "2026-01-01T00:00:00Z", investigator: "alice" };

function investigation(caseId = "INC-1") {
  return {
    caseId,
    findings: [{ id: "f1" }, { id: "f2" }],
    iocs: [{ id: "i1" }],
    forensicTimeline: [{ id: "e1" }, { id: "e2" }, { id: "e3" }],
  };
}

describe("buildSnapshot", () => {
  it("stamps the envelope, allowlists state, and computes counts", () => {
    const snap = buildSnapshot({
      caseMeta: META,
      state: {
        "investigation.json": investigation(),
        "comments.json": [{ id: "c1" }],
        // excluded files must be dropped even if handed in
        "enrich-control.json": ["VirusTotal"],
        "notion-export.json": { pageId: "secret" },
        "ai-control.json": { enabled: true },
      },
      captures: [{ screenshotFile: "a.webp" }, { screenshotFile: "b.webp" }],
      imports: [{ filename: "thor.json" }],
      exportedAt: "2026-06-12T00:00:00Z",
      generatedBy: "9.9.9",
    });

    expect(snap.format).toBe(SNAPSHOT_FORMAT);
    expect(snap.version).toBe(SNAPSHOT_VERSION);
    expect(snap.generatedBy).toBe("9.9.9");
    expect(snap.case).toEqual(META);
    expect(snap.state).toHaveProperty("investigation.json");
    expect(snap.state).toHaveProperty("comments.json");
    // OPSEC: machine/account/config files are never bundled
    for (const excluded of SNAPSHOT_EXCLUDED_STATE_FILES) {
      expect(snap.state).not.toHaveProperty(excluded);
    }
    expect(snap.counts).toEqual({ forensicEvents: 3, findings: 2, iocs: 1, captures: 2, imports: 1 });
  });

  it("tolerates a missing/empty investigation", () => {
    const snap = buildSnapshot({
      caseMeta: META, state: {}, captures: [], imports: [],
      exportedAt: "t", generatedBy: "v",
    });
    expect(snap.counts).toEqual({ forensicEvents: 0, findings: 0, iocs: 0, captures: 0, imports: 0 });
    expect(snap.state).toEqual({});
  });
});

describe("sanitizeSnapshotState", () => {
  it("keeps only allowlisted, present entries", () => {
    const cleaned = sanitizeSnapshotState({
      "investigation.json": { caseId: "x" },
      "scope.json": null,                 // null dropped
      "../../etc/passwd": "evil",         // traversal name dropped (not on allowlist)
      "velo-hunt.json": [{ huntId: "H1" }], // excluded dropped
    });
    expect(Object.keys(cleaned)).toEqual(["investigation.json"]);
  });
});

describe("parseSnapshot", () => {
  function valid() {
    return buildSnapshot({
      caseMeta: META, state: { "investigation.json": investigation() },
      captures: [], imports: [], exportedAt: "t", generatedBy: "v",
    });
  }

  it("accepts a well-formed snapshot and re-allowlists its state", () => {
    const raw = { ...valid(), state: { "investigation.json": investigation(), "enrich-control.json": ["VirusTotal"] } };
    const snap = parseSnapshot(raw);
    expect(snap.case.caseId).toBe("INC-1");
    expect(snap.state).not.toHaveProperty("enrich-control.json");
    expect(snap.state).toHaveProperty("investigation.json");
  });

  it("rejects a non-snapshot payload", () => {
    expect(() => parseSnapshot({ hello: "world" })).toThrow(/not a DFIR Companion snapshot/);
    expect(() => parseSnapshot(null)).toThrow(/not a DFIR Companion snapshot/);
  });

  it("rejects a snapshot from a newer Companion version", () => {
    expect(() => parseSnapshot({ ...valid(), version: SNAPSHOT_VERSION + 1 })).toThrow(/newer than this Companion/);
  });

  it("rejects an invalid embedded case id", () => {
    const raw = { ...valid(), case: { ...META, caseId: "../evil" } };
    expect(() => parseSnapshot(raw)).toThrow(/not a valid case id/);
  });
});

describe("prepareImport", () => {
  it("rewrites the embedded case id in investigation.json and evidence records", () => {
    const snap = parseSnapshot(buildSnapshot({
      caseMeta: META,
      state: { "investigation.json": investigation("INC-1"), "tags.json": [{ id: "t1" }] },
      captures: [{ caseId: "INC-1", screenshotFile: "a.webp" }],
      imports: [{ caseId: "INC-1", filename: "thor.json" }],
      exportedAt: "t", generatedBy: "v",
    }));

    const prepared = prepareImport(snap, "INC-2");
    expect(prepared.caseMeta.caseId).toBe("INC-2");
    const inv = prepared.stateFiles.find((f) => f.filename === "investigation.json")!.json as { caseId: string };
    expect(inv.caseId).toBe("INC-2");
    // a case-id-agnostic file is carried through untouched
    expect(prepared.stateFiles.some((f) => f.filename === "tags.json")).toBe(true);
    expect((prepared.captures[0] as { caseId: string }).caseId).toBe("INC-2");
    expect((prepared.imports[0] as { caseId: string }).caseId).toBe("INC-2");
  });
});

describe("allowlist / exclusion sets are disjoint", () => {
  it("no file is both included and excluded", () => {
    const included = new Set<string>(SNAPSHOT_STATE_FILES);
    for (const excluded of SNAPSHOT_EXCLUDED_STATE_FILES) {
      expect(included.has(excluded)).toBe(false);
    }
  });

  it("includes hunt-outcomes.json (investigation data travels with the case) (#157)", () => {
    expect(new Set<string>(SNAPSHOT_STATE_FILES).has("hunt-outcomes.json")).toBe(true);
  });

  it("includes hypotheses.json (investigation data travels with the case) (#140)", () => {
    expect(new Set<string>(SNAPSHOT_STATE_FILES).has("hypotheses.json")).toBe(true);
  });

  it("includes dwell-windows.json in the snapshot allowlist", () => {
    expect(SNAPSHOT_STATE_FILES).toContain("dwell-windows.json");
  });

  it("excludes forensic-gate.json (a machine-local display preference, not investigation data)", () => {
    expect(SNAPSHOT_STATE_FILES).not.toContain("forensic-gate.json");
  });
});
