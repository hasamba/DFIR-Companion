// #2891 gap 2: the content tagger used to swallow its own errors and return nothing, so a failed run
// looked like a finished one and the settle demoted untagged rows. It now says which rows it did NOT
// finish on. A deliberate skip (tagger off, empty ruleset, super-only scope) is finished; an internal
// failure leaves every row it was handed unfinished; a failure after the grade write changes nothing.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { autoTagNewEvents } from "../../src/analysis/taggerAuto.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const RULES = `svc:
  any:
    - { field: message, contains: ['7045'] }
  tags: ['win-service']
  severity: High
`;

let dir: string;
let stateStore: StateStore;
let tagsStore: TagsStore;
let taggerStore: TaggerStore;
let warn: ReturnType<typeof vi.spyOn>;
const ROWS = () => [ev({ id: "e1", message: "service 7045" }), ev({ id: "e2", message: "plain" })];

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-tagger-outcome-"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  tagsStore = new TagsStore(cases);
  const def = join(dir, "default.yaml");
  await writeFile(def, RULES);
  taggerStore = new TaggerStore(join(dir, "user.yaml"), [def]);
  const st = await stateStore.load("c1");
  await stateStore.save({ ...st, forensicTimeline: ROWS() });
  delete process.env.TAGGER_AUTO;
  delete process.env.TAGGER_SCOPE;
  warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.TAGGER_AUTO;
  delete process.env.TAGGER_SCOPE;
  await rm(dir, { recursive: true, force: true });
});

const deps = () => ({ taggerStore, tagsStore, stateStore });

describe("autoTagNewEvents outcome (#2891)", () => {
  it("a finished run reports no unfinished row — matched-and-raised and unmatched alike", async () => {
    expect(await autoTagNewEvents(deps(), "c1", ROWS())).toEqual({ ungraded: [] });
    expect((await stateStore.load("c1")).forensicTimeline[0].severity).toBe("High");
  });

  it("an internal failure leaves every row it was handed unfinished, and says so at WARN", async () => {
    vi.spyOn(taggerStore, "load").mockRejectedValue(new Error("bad yaml"));
    expect(await autoTagNewEvents(deps(), "c1", ROWS())).toEqual({ ungraded: ["e1", "e2"] });
    expect(warn.mock.calls.some(([m]: unknown[]) => /auto-tag failed.*bad yaml/.test(String(m)))).toBe(true);
  });

  it("a failed grade write leaves the rows unfinished", async () => {
    vi.spyOn(stateStore, "updateForensicRows").mockRejectedValue(new Error("disk full"));
    expect(await autoTagNewEvents(deps(), "c1", ROWS())).toEqual({ ungraded: ["e1", "e2"] });
  });

  it("a grade write refused for good (version conflict) leaves only that row unfinished", async () => {
    vi.spyOn(stateStore, "updateForensicRows").mockImplementation(async (_caseId, rows) => ({
      updated: 0,
      missing: [],
      conflicts: rows.map((r) => r.rowId),
    }));
    expect(await autoTagNewEvents(deps(), "c1", ROWS())).toEqual({ ungraded: ["e1"] });
  });

  it("a failure AFTER the grade write (the run ledger) does not unmark the rows", async () => {
    const analysisRunStore = { record: vi.fn().mockRejectedValue(new Error("ledger down")) };
    const out = await autoTagNewEvents({ ...deps(), analysisRunStore } as never, "c1", ROWS());
    expect(out).toEqual({ ungraded: [] });
    expect((await stateStore.load("c1")).forensicTimeline[0].severity).toBe("High");
  });

  it("deliberate skips are finished: tagger off, super-only scope, no tagger wired", async () => {
    process.env.TAGGER_AUTO = "false";
    expect(await autoTagNewEvents(deps(), "c1", ROWS())).toEqual({ ungraded: [] });
    delete process.env.TAGGER_AUTO;
    process.env.TAGGER_SCOPE = "super";
    expect(await autoTagNewEvents(deps(), "c1", ROWS())).toEqual({ ungraded: [] });
    expect(await autoTagNewEvents({ stateStore }, "c1", ROWS())).toEqual({ ungraded: [] });
  });
});
