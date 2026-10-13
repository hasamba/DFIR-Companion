import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { TaggerStore } from "../../src/analysis/taggerStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { settleForensicImport, type SettleDeps } from "../../src/routes/importSettle.js";
import { createImportDemote } from "../../src/composition/importDemote.js";
import { autoTagNewEvents } from "../../src/analysis/taggerAuto.js";
import { captureImportBaseline, releaseImportBaseline } from "../../src/analysis/importBaseline.js";
import type { AppOptions } from "../../src/composition/appOptions.js";

// #2182: re-importing the same evidence (same ids) restates the row's raw Info grade. The tagger
// raised it to High on the first import; the re-import must keep High, so the demote gate does not
// move it out of the forensic timeline, and must record no "changed after first recorded" entry.

const RULES = `spooler:
  any:
    - { field: message, contains: ['Spooler'] }
  tags: ['spooler']
  mitre: ['T1543.003']
  severity: High
`;
const evidence = JSON.stringify([
  {
    "@timestamp": "2026-07-01T11:00:00.000Z",
    log_name: "System",
    computer_name: "S1-HOST",
    event_id: 7036,
    level: "Information",
    message: "The Print Spooler service entered the running state.",
  },
]);

let root: string;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let tagsStore: TagsStore;
let taggerStore: TaggerStore;
let lock: StateLock;
let pipeline: AnalysisPipeline;
let gate: ForensicGateControlStore;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "settle-retag-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  stateStore = new StateStore(cases);
  superStore = new SuperTimelineStore(cases);
  tagsStore = new TagsStore(cases);
  await writeFile(join(root, "rules.yaml"), RULES);
  taggerStore = new TaggerStore(join(root, "user.yaml"), [join(root, "rules.yaml")]);
  lock = new StateLock();
  pipeline = new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    stateLock: lock,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  gate = new ForensicGateControlStore(cases);
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const runExclusive = <T>(c: string, fn: () => Promise<T>) => lock.runExclusive(c, fn);

function deps(): SettleDeps {
  const options = {
    stateStore,
    superTimelineStore: superStore,
    forensicGateControlStore: gate,
  } as unknown as AppOptions;
  const demote = createImportDemote({ options, runStateExclusive: runExclusive });
  return {
    stateStore,
    runStateExclusive: runExclusive,
    superTimelineStore: superStore,
    autoTagImported: (c, added) =>
      autoTagNewEvents({ taggerStore, tagsStore, stateStore, runStateExclusive: runExclusive }, c, added),
    demoteForensic: demote.demoteForensic,
  };
}

async function importOnce(label: string) {
  const baseline = await captureImportBaseline(stateStore, "c1");
  try {
    await pipeline.importSiem("c1", evidence, { label, idPrefix: "1", importedAt: "2026-09-01T00:00:00Z" });
    return await settleForensicImport(deps(), "c1", baseline, label);
  } finally {
    await releaseImportBaseline(stateStore, baseline);
  }
}

describe("settleForensicImport — a re-import keeps the tagger's grade (#2182)", () => {
  it("re-importing the same file with the same ids keeps the row at High, unrevised", async () => {
    await importOnce("a.json");
    const first = await stateStore.load("c1");
    expect(first.forensicTimeline.map((e) => e.severity)).toEqual(["High"]);

    const settled = await importOnce("a-again.json");
    const second = await stateStore.load("c1");
    expect(second.forensicTimeline.map((e) => [e.id, e.severity])).toEqual([
      [first.forensicTimeline[0].id, "High"],
    ]);
    expect(second.forensicTimeline[0].revisions).toBeUndefined();
    expect(settled.timelineDiff?.removed ?? []).toEqual([]);
  });
});
