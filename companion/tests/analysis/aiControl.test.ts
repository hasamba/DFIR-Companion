import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";

let cases: CaseStore;
let control: AiControlStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-aictl-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  control = new AiControlStore(cases);
});

describe("AiControlStore", () => {
  it("defaults to enabled with lastAnalyzedSeq 0 when none saved", async () => {
    const c = await control.load("c1");
    expect(c.enabled).toBe(true);
    expect(c.lastAnalyzedSeq).toBe(0);
  });

  it("round-trips saved control", async () => {
    await control.save("c1", { enabled: false, lastAnalyzedSeq: 12 });
    const c = await control.load("c1");
    expect(c.enabled).toBe(false);
    expect(c.lastAnalyzedSeq).toBe(12);
  });
});
