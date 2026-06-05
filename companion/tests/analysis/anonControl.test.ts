import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnonControlStore, toAnonPolicy } from "../../src/analysis/anonControl.js";

let cases: CaseStore;
let store: AnonControlStore;
const ENV = process.env.DFIR_ANONYMIZE;

beforeEach(async () => {
  delete process.env.DFIR_ANONYMIZE;
  const root = await mkdtemp(join(tmpdir(), "dfir-anon-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new AnonControlStore(cases);
});
afterEach(() => { if (ENV === undefined) delete process.env.DFIR_ANONYMIZE; else process.env.DFIR_ANONYMIZE = ENV; });

describe("AnonControlStore", () => {
  it("defaults to enabled with all categories on", async () => {
    const c = await store.load("c1");
    expect(c.enabled).toBe(true);
    expect(c.categories.IP).toBe(true);
    expect(c.redactSecrets).toBe(true);
  });
  it("DFIR_ANONYMIZE=off flips the default to disabled", async () => {
    process.env.DFIR_ANONYMIZE = "off";
    expect((await store.load("c1")).enabled).toBe(false);
  });
  it("round-trips a saved control and merges new categories over the default", async () => {
    await store.save("c1", { enabled: false, categories: { IP: false, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true }, redactSecrets: false });
    const c = await store.load("c1");
    expect(c.enabled).toBe(false);
    expect(c.categories.IP).toBe(false);
    expect(c.redactSecrets).toBe(false);
  });
});

describe("toAnonPolicy", () => {
  it("null control → disabled policy", () => {
    expect(toAnonPolicy(null).enabled).toBe(false);
  });
});
