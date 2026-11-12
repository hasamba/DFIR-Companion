import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { presidioHeldSynthesis, SYNTHESIS_HOLD_FEATURES } from "../../src/analysis/aiState.js";

let cases: CaseStore;
let store: PresidioPendingStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidiopending-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new PresidioPendingStore(cases);
});

describe("PresidioPendingStore", () => {
  it("returns an empty list for a case with no pending file", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("round-trips findings", async () => {
    await store.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
    expect(await store.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("sanitizes on save, coercing an unknown category to OTHER", async () => {
    await store.save("c1", [{ value: "x", category: "NOPE" } as never]);
    expect(await store.load("c1")).toEqual([{ value: "x", category: "OTHER" }]);
  });

  it("clear empties the list", async () => {
    await store.save("c1", [{ value: "Jane Doe", category: "PERSON" }]);
    await store.clear("c1");
    expect(await store.load("c1")).toEqual([]);
  });
});

// The pending file records which features the gate held, so clearing it can tell a held synthesis
// from a held hunt suggestion. The record lasts the whole approval round.
describe("PresidioPendingStore held features", () => {
  const jane = { value: "Jane Doe", category: "PERSON" as const };
  const john = { value: "John Smith", category: "PERSON" as const };

  it("records the feature a hold names", async () => {
    await store.hold("c1", [jane], "suggest-language-hunts");
    expect(await store.load("c1")).toEqual([jane]);
    expect(await store.heldFeatures("c1")).toEqual(["suggest-language-hunts"]);
  });

  it("adds a second hold in the same round instead of replacing the first", async () => {
    await store.hold("c1", [jane], "synthesis");
    await store.hold("c1", [john], "suggest-language-hunts");
    expect(await store.heldFeatures("c1")).toEqual(["synthesis", "suggest-language-hunts"]);
  });

  it("keeps the record through a partial approval and after the list empties", async () => {
    await store.hold("c1", [jane, john], "synthesis");
    await store.save("c1", [john]);
    expect(await store.heldFeatures("c1")).toEqual(["synthesis"]);
    await store.save("c1", []);
    expect(await store.heldFeatures("c1")).toEqual(["synthesis"]);
  });

  it("starts a new round on the first hold after the list emptied", async () => {
    await store.hold("c1", [jane], "synthesis");
    await store.save("c1", []);
    await store.hold("c1", [john], "suggest-language-hunts");
    expect(await store.heldFeatures("c1")).toEqual(["suggest-language-hunts"]);
  });

  it("reports null for a file written before features were recorded", async () => {
    await writeFile(join(cases.stateDir("c1"), "presidio-pending.json"), JSON.stringify({ pending: [jane] }));
    expect(await store.heldFeatures("c1")).toBeNull();
    // ...and a hold in that same round keeps it unknown rather than inventing a record.
    await store.hold("c1", [jane, john], "suggest-language-hunts");
    expect(await store.heldFeatures("c1")).toBeNull();
  });

  it("reports null when the list was only ever saved, never held", async () => {
    await store.save("c1", [jane]);
    expect(await store.heldFeatures("c1")).toBeNull();
  });
});

describe("presidioHeldSynthesis", () => {
  it("is true when a synthesis-family feature was held", () => {
    for (const f of SYNTHESIS_HOLD_FEATURES) expect(presidioHeldSynthesis([f]), f).toBe(true);
    expect(presidioHeldSynthesis(["suggest-language-hunts", "synthesis"])).toBe(true);
  });

  it("is false when only on-demand features were held", () => {
    expect(presidioHeldSynthesis(["suggest-language-hunts"])).toBe(false);
    expect(presidioHeldSynthesis(["translate-query", "jev"])).toBe(false);
  });

  it("takes the safe side when nothing is known", () => {
    expect(presidioHeldSynthesis(null)).toBe(true);
    expect(presidioHeldSynthesis([])).toBe(true);
  });
});
