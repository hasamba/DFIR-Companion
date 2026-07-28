import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { EnrichControlStore, resolveEnabledProviders } from "../../src/enrichment/enrichControl.js";

const configured = ["VirusTotal", "AbuseIPDB", "MISP", "YETI"];
const local = ["MISP", "YETI"];

describe("resolveEnabledProviders", () => {
  it("defaults to local-only when nothing is stored (OPSEC-safe)", () => {
    expect(resolveEnabledProviders(null, configured, local)).toEqual(["MISP", "YETI"]);
  });

  it("keeps an explicit list, filtered to providers still configured", () => {
    expect(resolveEnabledProviders({ providers: ["VirusTotal", "MISP", "GoneProvider"] }, configured, local))
      .toEqual(["VirusTotal", "MISP"]);
  });

  it("explicit empty list means none (enrichment off)", () => {
    expect(resolveEnabledProviders({ providers: [] }, configured, local)).toEqual([]);
  });

  it("migrates legacy { enabled } — true → all configured, false → none", () => {
    expect(resolveEnabledProviders({ enabled: true }, configured, local)).toEqual(configured);
    expect(resolveEnabledProviders({ enabled: false }, configured, local)).toEqual([]);
  });
});

describe("EnrichControlStore.load — corrupt-file resilience (#6)", () => {
  it("returns null for an empty/corrupt enrich-control.json instead of throwing", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-enrichctrl-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new EnrichControlStore(cases);
    // Write a corrupt (empty) control file — a crash mid-write or a sync conflict.
    await writeFile(join(cases.stateDir("c1"), "enrich-control.json"), "");
    // load must NOT throw; it returns null so the case degrades to the default.
    await expect(store.load("c1")).resolves.toBeNull();
    // And resolveEnabledProviders(null, ...) gives the OPSEC-safe local-only default.
    expect(resolveEnabledProviders(await store.load("c1"), configured, local)).toEqual(["MISP", "YETI"]);
  });

  it("returns null for a truncated/invalid-JSON control file", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-enrichctrl-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const store = new EnrichControlStore(cases);
    await writeFile(join(cases.stateDir("c1"), "enrich-control.json"), '{providers:["VirusTotal"');
    await expect(store.load("c1")).resolves.toBeNull();
  });
});
