import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { StateFileCorruptError } from "../../src/storage/stateFileCorrupt.js";

let cases: CaseStore;
let control: AiControlStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-aictl-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  control = new AiControlStore(cases);
});

describe("AiControlStore", () => {
  it("defaults to disabled with lastAnalyzedSeq 0 when none saved", async () => {
    const c = await control.load("c1");
    expect(c.enabled).toBe(false);
    expect(c.lastAnalyzedSeq).toBe(0);
  });

  it("round-trips saved control", async () => {
    await control.save("c1", { enabled: false, lastAnalyzedSeq: 12 });
    const c = await control.load("c1");
    expect(c.enabled).toBe(false);
    expect(c.lastAnalyzedSeq).toBe(12);
  });
});

// #2760: a damaged file rejected with a bare SyntaxError that named neither the case nor the file.
describe("AiControlStore on a damaged file", () => {
  it.each(["{corrupt", "null", "[1,2]", "42"])(
    "rejects %s with StateFileCorruptError naming case and file",
    async (text) => {
      await writeFile(join(cases.stateDir("c1"), "ai-control.json"), text);
      const err = await control.load("c1").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(StateFileCorruptError);
      expect((err as StateFileCorruptError).file).toBe("ai-control.json");
      expect((err as Error).message).toContain("c1");
      expect((err as Error).message).toContain("ai-control.json");
    },
  );
});
