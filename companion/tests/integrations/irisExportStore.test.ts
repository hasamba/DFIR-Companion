import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { IrisExportStore, defaultIrisCaseName } from "../../src/integrations/iris/irisExportStore.js";

describe("defaultIrisCaseName", () => {
  it("combines the Companion case id and friendly name", () => {
    expect(defaultIrisCaseName("c1", "Ransomware FS01")).toBe("c1 — Ransomware FS01");
  });

  it("falls back to just the case id when there is no friendly name", () => {
    expect(defaultIrisCaseName("c1", "")).toBe("c1");
    expect(defaultIrisCaseName("c1", undefined)).toBe("c1");
    expect(defaultIrisCaseName("c1", null)).toBe("c1");
  });
});

describe("IrisExportStore", () => {
  let store: IrisExportStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-iris-export-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new IrisExportStore(cases);
  });

  it("returns an empty caseName before anything has been pushed", async () => {
    expect(await store.load("c1")).toEqual({ caseName: "" });
  });

  it("remembers the last pushed case name, overwriting the previous one", async () => {
    await store.record("c1", "acme-breach-2026");
    expect(await store.load("c1")).toEqual({ caseName: "acme-breach-2026" });
    await store.record("c1", "renamed-case");
    expect(await store.load("c1")).toEqual({ caseName: "renamed-case" });
  });
});
