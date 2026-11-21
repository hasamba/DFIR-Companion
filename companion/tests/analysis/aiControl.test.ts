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

// A hand-edited or imported file whose switch is not a real boolean ("false", "yes", 1, null …) was
// read as AI ON by truthiness. Anything but a boolean is damage: the file fails closed.
describe("AiControlStore on a file whose fields have the wrong type", () => {
  const bad: Array<[string, Record<string, unknown>]> = [
    ['enabled "false"', { enabled: "false" }],
    ['enabled "true"', { enabled: "true" }],
    ['enabled "yes"', { enabled: "yes" }],
    ["enabled 1", { enabled: 1 }],
    ["enabled 0", { enabled: 0 }],
    ["enabled null", { enabled: null }],
    ["enabled {}", { enabled: {} }],
    ["enabled []", { enabled: [] }],
    ['includeNotebook "false"', { enabled: false, includeNotebook: "false" }],
    ["includeNotebook 1", { enabled: false, includeNotebook: 1 }],
    ['lastAnalyzedSeq "5"', { enabled: false, lastAnalyzedSeq: "5" }],
    ["lastAnalyzedSeq 1.5", { enabled: false, lastAnalyzedSeq: 1.5 }],
    ["lastAnalyzedSeq null", { enabled: false, lastAnalyzedSeq: null }],
    ['inFlightSeqs "3"', { enabled: false, inFlightSeqs: "3" }],
    ['inFlightSeqs ["3"]', { enabled: false, inFlightSeqs: ["3"] }],
    ['analysisHold "x"', { enabled: false, analysisHold: "x" }],
    [
      "analysisHold without failedSeqs",
      { enabled: false, analysisHold: { analyzedThrough: 1, attempts: 0 } },
    ],
  ];

  it.each(bad)("rejects %s with StateFileCorruptError naming the field", async (_label, record) => {
    await writeFile(join(cases.stateDir("c1"), "ai-control.json"), JSON.stringify(record));
    const err = await control.load("c1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StateFileCorruptError);
    expect((err as StateFileCorruptError).file).toBe("ai-control.json");
    const field = Object.keys(record).find((k) => k !== "enabled") ?? "enabled";
    expect((err as Error).message).toContain(field);
  });

  it("accepts a well-typed record with every optional field", async () => {
    const record = {
      enabled: true,
      lastAnalyzedSeq: 4,
      includeNotebook: false,
      watsonRunMode: "auto",
      watsonAutoSince: "2026-01-01T00:00:00.000Z",
      watsonAutoBy: { name: "analyst" },
      inFlightSeqs: [5, 6],
      analysisHold: { failedSeqs: [3], analyzedThrough: 4, attempts: 1, gaveUp: false },
    };
    await writeFile(join(cases.stateDir("c1"), "ai-control.json"), JSON.stringify(record));
    expect(await control.load("c1")).toEqual(record);
  });

  it("reads a record with no enabled field as AI off, not as damage", async () => {
    await writeFile(join(cases.stateDir("c1"), "ai-control.json"), JSON.stringify({ lastAnalyzedSeq: 2 }));
    expect(await control.load("c1")).toEqual({ enabled: false, lastAnalyzedSeq: 2 });
  });
});
