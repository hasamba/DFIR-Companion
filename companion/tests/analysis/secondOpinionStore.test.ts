import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import type { SecondOpinion } from "../../src/analysis/secondOpinion.js";

const SO: SecondOpinion = {
  generatedAt: "2026-06-15T00:00:00.000Z",
  modelA: "claude-opus",
  modelB: "gpt-4o",
  summary: "B is more thorough on C2.",
  agreementCount: 3,
  deltas: [
    {
      id: "b_only:cobalt-strike-c2-beacon",
      kind: "b_only",
      title: "Cobalt Strike C2 beacon",
      bSeverity: "High",
      finding: {
        id: "g3", severity: "High", confidence: 75, title: "Cobalt Strike C2 beacon",
        description: "beacon", relatedIocs: ["i9"], sourceScreenshots: [], mitreTechniques: ["T1071"],
        firstSeen: "2026-06-01T00:00:00.000Z", lastUpdated: "2026-06-01T00:00:00.000Z", status: "open",
      },
      rationale: "Backed by IOC i9.",
      recommendation: "accept_b",
      status: "pending",
    },
    {
      id: "severity:suspicious-logon", kind: "severity", title: "Suspicious logon",
      aSeverity: "Medium", bSeverity: "High", rationale: "", recommendation: "review", status: "accepted",
    },
  ],
};

describe("SecondOpinionStore", () => {
  let store: SecondOpinionStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-secondopinion-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new SecondOpinionStore(cases);
  });

  it("returns null when none exists", async () => {
    expect(await store.load("c1")).toBeNull();
  });

  it("saves a record and loads it back faithfully", async () => {
    await store.save("c1", SO);
    expect(await store.load("c1")).toEqual(SO);
  });

  it("overwrites on the next save", async () => {
    await store.save("c1", SO);
    const next: SecondOpinion = { ...SO, summary: "changed", deltas: [] };
    await store.save("c1", next);
    expect(await store.load("c1")).toEqual(next);
  });

  it("clears the record (load returns null again)", async () => {
    await store.save("c1", SO);
    await store.clear("c1");
    expect(await store.load("c1")).toBeNull();
    // clearing again is a no-op, not an error
    await expect(store.clear("c1")).resolves.toBeUndefined();
  });

  it("coerces a malformed persisted recommendation/status to safe defaults", async () => {
    await store.save("c1", { ...SO, deltas: [{ ...SO.deltas[0], recommendation: "bogus" as never, status: "weird" as never }] });
    const loaded = await store.load("c1");
    expect(loaded!.deltas[0].recommendation).toBe("review");
    expect(loaded!.deltas[0].status).toBe("pending");
  });
});
