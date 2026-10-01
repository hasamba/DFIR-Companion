import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
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

  it("keeps a valid raster logo data URI and the company name", () => {
    const logo =
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    const m = normalizeReportMeta({ companyName: "Acme DFIR", companyLogo: logo });
    expect(m.companyName).toBe("Acme DFIR");
    expect(m.companyLogo).toBe(logo);
  });

  it("rejects non-raster / malformed / oversized logos (falls back to no logo)", () => {
    // SVG is rejected (could carry script into the rendered HTML report).
    expect(
      normalizeReportMeta({ companyLogo: "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=" }).companyLogo,
    ).toBe("");
    // A non-data URL is not an inline image.
    expect(normalizeReportMeta({ companyLogo: "https://evil.example/logo.png" }).companyLogo).toBe("");
    // Wrong type entirely.
    expect(normalizeReportMeta({ companyLogo: 12345 }).companyLogo).toBe("");
    // Over the length cap collapses to "".
    expect(
      normalizeReportMeta({ companyLogo: "data:image/png;base64," + "A".repeat(1_000_001) }).companyLogo,
    ).toBe("");
  });

  it("never throws on garbage input — falls back to defaults", () => {
    expect(normalizeReportMeta("nonsense")).toEqual(emptyReportMeta());
    expect(normalizeReportMeta(null)).toEqual(emptyReportMeta());
    expect(normalizeReportMeta(42)).toEqual(emptyReportMeta());
    // wrong-typed field falls back to its default without rejecting the whole object
    expect(normalizeReportMeta({ revisions: "not-an-array", organization: "ok" })).toMatchObject({
      revisions: [],
      organization: "ok",
    });
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

  it("returns empty defaults, seeded with the creation-time investigator, when no file exists yet", async () => {
    const m = await store.load("case-1");
    expect(m).toEqual({ ...emptyReportMeta(), investigators: ["i"] });
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

// #1913: the investigator typed at case creation lives in case.json; the Case Details form and every
// report read report-meta.json's own list, which nothing seeded — so both showed "(investigator not
// set)" for a case that had one. Until the analyst saves Case Details, the creation-time investigator
// is the list. Once saved, the saved list is returned as saved, an empty one included.
describe("ReportMetaStore — creation-time investigator (#1913)", () => {
  async function storeFor(investigator: string) {
    const root = await mkdtemp(join(tmpdir(), "dfir-reportmeta-inv-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator, aiProvider: null });
    return new ReportMetaStore(cases);
  }

  it("seeds the list from the case when Case Details was never saved", async () => {
    const store = await storeFor("  Alice Example  ");
    expect((await store.load("c1")).investigators).toEqual(["Alice Example"]);
  });

  it("keeps a list the analyst saved, and does not re-add the creator", async () => {
    const store = await storeFor("Alice Example");
    await store.save("c1", { investigators: ["Bob Example"] });
    expect((await store.load("c1")).investigators).toEqual(["Bob Example"]);
  });

  it("keeps a saved empty list empty, so the round trip holds and the analyst can clear it", async () => {
    const store = await storeFor("Alice Example");
    const saved = await store.save("c1", { organization: "ExampleCorp" });
    expect(await store.load("c1")).toEqual(saved);
    expect(saved.investigators).toEqual([]);
  });

  it("seeds nothing from a blank or placeholder investigator", async () => {
    for (const placeholder of ["", "   ", "unknown", "Unknown"]) {
      const store = await storeFor(placeholder);
      expect((await store.load("c1")).investigators, JSON.stringify(placeholder)).toEqual([]);
    }
  });

  it("seeds nothing, and does not throw, for a case that does not exist", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-reportmeta-inv-"));
    const store = new ReportMetaStore(new CaseStore(root));
    expect(await store.load("ghost")).toEqual(emptyReportMeta());
  });

  it("a corrupt case.json fails the load visibly instead of dropping the investigator", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-reportmeta-inv-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "alice", aiProvider: null });
    await writeFile(join(root, "c1", "case.json"), "{not json", "utf8");
    await expect(new ReportMetaStore(cases).load("c1")).rejects.toThrow();
  });
});
