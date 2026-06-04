import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ReportMetaStore, emptyReportMeta, normalizeReportMeta } from "../../src/reports/reportMeta.js";

describe("normalizeReportMeta", () => {
  it("defaults missing fields and turns the disclaimer on by default", () => {
    const m = normalizeReportMeta({});
    expect(m.organization).toBe("");
    expect(m.revisions).toEqual([]);
    expect(m.recommendations).toEqual([]);
    expect(m.includeDisclaimer).toBe(true);
  });

  it("keeps valid fields and drops unknown keys", () => {
    const m = normalizeReportMeta({
      organization: "ExampleCorp",
      investigator: "Jane Doe",
      recommendations: ["a", "b"],
      glossary: [{ term: "EDR", explanation: "Endpoint Detection and Response" }],
      bogusKey: "should be dropped",
    });
    expect(m.organization).toBe("ExampleCorp");
    expect(m.recommendations).toEqual(["a", "b"]);
    expect(m.glossary[0]).toEqual({ term: "EDR", explanation: "Endpoint Detection and Response" });
    expect(m).not.toHaveProperty("bogusKey");
  });

  it("never throws on garbage input — falls back to defaults", () => {
    expect(normalizeReportMeta("nonsense")).toEqual(emptyReportMeta());
    expect(normalizeReportMeta(null)).toEqual(emptyReportMeta());
    expect(normalizeReportMeta(42)).toEqual(emptyReportMeta());
    // wrong-typed field falls back to its default without rejecting the whole object
    expect(normalizeReportMeta({ revisions: "not-an-array", organization: "ok" }))
      .toMatchObject({ revisions: [], organization: "ok" });
  });
});

describe("ReportMetaStore", () => {
  let store: ReportMetaStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-reportmeta-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "case-1", name: "n", investigator: "i", aiProvider: null });
    store = new ReportMetaStore(cases);
  });

  it("returns empty defaults when no file exists yet", async () => {
    const m = await store.load("case-1");
    expect(m).toEqual(emptyReportMeta());
  });

  it("persists and reloads a normalized value (round-trip)", async () => {
    const saved = await store.save("case-1", {
      organization: "ExampleCorp",
      incidentId: "INC-123456",
      distribution: [{ name: "CISO", role: "Chief Information Security Officer", method: "email" }],
      includeDisclaimer: false,
      junk: "dropped",
    });
    expect(saved.organization).toBe("ExampleCorp");
    expect(saved.includeDisclaimer).toBe(false);

    const reloaded = await store.load("case-1");
    expect(reloaded).toEqual(saved);
    expect(reloaded.distribution[0].name).toBe("CISO");
  });
});
