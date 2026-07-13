import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { autoTagNewEvents } from "../../src/analysis/taggerAuto.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { timestamp: "2026-06-01T00:00:00Z", description: "d", severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...p };
}

const RULES = `svc:
  any:
    - { field: message, contains: ['7045'] }
  tags: ['win-service']
  mitre: ['T1543']
  severity: High
`;

let dir: string;
let cases: CaseStore;
let stateStore: StateStore;
let tagsStore: TagsStore;
let taggerStore: TaggerStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-tagger-auto-"));
  cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  tagsStore = new TagsStore(cases);
  const def = join(dir, "default.yaml");
  await writeFile(def, RULES);
  taggerStore = new TaggerStore(join(dir, "user.yaml"), [def]);
  // Seed the forensic timeline with the same event the import "added".
  const st = await stateStore.load("c1");
  await stateStore.save({ ...st, forensicTimeline: [ev({ id: "e1", message: "service 7045", severity: "Low" })] });
  delete process.env.TAGGER_AUTO;
  delete process.env.TAGGER_SCOPE;
  delete process.env.TAGGER_RULES_FILE;
});

afterEach(async () => {
  delete process.env.TAGGER_AUTO;
  delete process.env.TAGGER_SCOPE;
  await rm(dir, { recursive: true, force: true });
});

const deps = () => ({ taggerStore, tagsStore, stateStore });

describe("autoTagNewEvents", () => {
  it("tags new events and raises forensic severity by default (TAGGER_AUTO on)", async () => {
    await autoTagNewEvents(deps(), "c1", [ev({ id: "e1", message: "service 7045", severity: "Low" })]);
    const tags = await tagsStore.load("c1");
    expect(tags.map((t) => t.label)).toContain("win-service");
    expect(tags.every((t) => t.author === "tagger:svc")).toBe(true);
    const st = await stateStore.load("c1");
    expect(st.forensicTimeline[0].severity).toBe("High");
    expect(st.forensicTimeline[0].mitreTechniques).toContain("T1543");
  });

  it("does nothing when TAGGER_AUTO=false", async () => {
    process.env.TAGGER_AUTO = "false";
    await autoTagNewEvents(deps(), "c1", [ev({ id: "e1", message: "service 7045" })]);
    expect(await tagsStore.load("c1")).toHaveLength(0);
  });

  it("scope=super tags but does NOT mutate the forensic timeline", async () => {
    process.env.TAGGER_SCOPE = "super";
    await autoTagNewEvents(deps(), "c1", [ev({ id: "e1", message: "service 7045", severity: "Low" })]);
    expect((await tagsStore.load("c1")).map((t) => t.label)).toContain("win-service");
    const st = await stateStore.load("c1");
    expect(st.forensicTimeline[0].severity).toBe("Low"); // untouched
  });

  it("never throws on an invalid ruleset (best-effort)", async () => {
    const badDir = await mkdtemp(join(tmpdir(), "dfir-tagger-bad-"));
    const badDefault = join(badDir, "bad.yaml");
    await writeFile(badDefault, "bad:\n  any:\n    - { field: nope, contains: x }\n  tags: ['t']\n");
    const badStore = new TaggerStore(join(badDir, "user.yaml"), [badDefault]);
    await expect(
      autoTagNewEvents({ taggerStore: badStore, tagsStore, stateStore }, "c1", [ev({ id: "e1", message: "x" })]),
    ).resolves.toBeUndefined();
    await rm(badDir, { recursive: true, force: true });
  });
});
