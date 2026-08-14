import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
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
afterEach(() => {
  if (ENV === undefined) delete process.env.DFIR_ANONYMIZE;
  else process.env.DFIR_ANONYMIZE = ENV;
});

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
    await store.save("c1", {
      enabled: false,
      categories: {
        IP: false,
        EMAIL: true,
        USER: true,
        HOST: true,
        DOMAIN: true,
        PATH: true,
        CMD: true,
        REG: true,
        CARD: true,
        PHONE: true,
        NATID: true,
      },
      redactSecrets: false,
      presidio: false,
    });
    const c = await store.load("c1");
    expect(c.enabled).toBe(false);
    expect(c.categories.IP).toBe(false);
    expect(c.redactSecrets).toBe(false);
    expect(c.presidio).toBe(false);
  });

  it("defaults Presidio scanning ON", async () => {
    expect((await store.load("c1")).presidio).toBe(true);
  });

  // Every control file written before the switch existed lacks the key. Treating a missing key as
  // `false` would silently stand the name-detection layer down on every existing case the first
  // time this version boots — a coverage loss nobody asked for and nothing would report.
  it("treats a control file written before the switch existed as ON, not off", async () => {
    const legacy = {
      enabled: true,
      categories: { IP: true },
      redactSecrets: true,
    };
    await writeFile(join(cases.stateDir("c1"), "anon-control.json"), JSON.stringify(legacy));
    expect((await store.load("c1")).presidio).toBe(true);
  });

  it("round-trips the switch back on again", async () => {
    const cur = await store.load("c1");
    await store.save("c1", { ...cur, presidio: false });
    expect((await store.load("c1")).presidio).toBe(false);
    await store.save("c1", { ...cur, presidio: true });
    expect((await store.load("c1")).presidio).toBe(true);
  });
});

describe("toAnonPolicy", () => {
  it("null control → disabled policy", () => {
    expect(toAnonPolicy(null).enabled).toBe(false);
  });
});
