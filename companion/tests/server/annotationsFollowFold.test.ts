// #1715: a tag, star or comment an analyst put on an event must follow it when correlation later folds
// that event into another. The stored record keeps the id the analyst marked; the list the dashboard
// reads carries `resolvedTargetId`, the event it lives on today.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

const HASH = "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef";
const ctx = { windowSequence: 1, timestamp: "2026-05-28T10:00:00.000Z", sourceScreenshots: [] };
const baseDelta: AnalysisDelta = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};
type DeltaEvent = NonNullable<AnalysisDelta["forensicEvents"]>[number];
const ev = (over: Partial<ForensicEvent> & { id: string }) =>
  ({
    timestamp: "2026-05-26T08:35:23Z",
    description: "event",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  }) as DeltaEvent;
const velo = ev({ id: "m1e1", description: `Downloaded file evil.exe flagged, sha256 ${HASH}` });
const thor = ev({
  id: "t2e5",
  severity: "Critical",
  sha256: HASH,
  description: "THOR Alert: Malware file found C:\\Tools\\evil.exe",
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-1715-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const app = createApp(store, {
    aiConfigured: false,
    stateStore,
    tagsStore: new TagsStore(store),
    commentsStore: new CommentsStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  // The analyst's velociraptor row is stored first …
  const first = mergeDelta(emptyState("c1"), { ...baseDelta, forensicEvents: [velo] }, ctx);
  await stateStore.save(first);
  return { app, stateStore, first };
}

/** … then a THOR import folds it into the more severe detection. */
async function foldIt(stateStore: StateStore, first: ReturnType<typeof mergeDelta>) {
  await stateStore.save(mergeDelta(first, { ...baseDelta, forensicEvents: [thor] }, ctx));
}

describe("annotations follow an event correlation folded away (#1715)", () => {
  it("a tag and a comment on the folded event carry the survivor as resolvedTargetId", async () => {
    const { app, stateStore, first } = await harness();
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "m1e1", label: "key-evidence", author: "an" });
    await request(app)
      .post("/cases/c1/comments")
      .send({ targetType: "event", targetId: "m1e1", text: "seen on the host", author: "an" });
    await foldIt(stateStore, first);

    const tags = (await request(app).get("/cases/c1/tags")).body;
    expect(tags).toHaveLength(1);
    expect(tags[0]).toMatchObject({ targetId: "m1e1", resolvedTargetId: "t2e5", label: "key-evidence" });
    const comments = (await request(app).get("/cases/c1/comments")).body;
    expect(comments[0]).toMatchObject({ targetId: "m1e1", resolvedTargetId: "t2e5" });
  });

  it("leaves a live target, and a non-event target, exactly as stored", async () => {
    const { app, stateStore, first } = await harness();
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "finding", targetId: "m1e1", label: "needs-review", author: "an" });
    await foldIt(stateStore, first);
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "t2e5", label: "pivot-point", author: "an" });

    const tags = (await request(app).get("/cases/c1/tags")).body as Array<Record<string, unknown>>;
    expect(tags.every((t) => !("resolvedTargetId" in t))).toBe(true);
  });

  it("a folded-away id that is an event again resolves to itself", async () => {
    const { app, stateStore, first } = await harness();
    await request(app)
      .post("/cases/c1/tags")
      .send({ targetType: "event", targetId: "m1e1", label: "starred", author: "an" });
    await foldIt(stateStore, first);
    const folded = await stateStore.load("c1");
    // An unrelated row that happens to reuse the id (e.g. a bulk append) is live again.
    await stateStore.save({
      ...folded,
      forensicTimeline: [
        ...folded.forensicTimeline,
        { ...velo, id: "m1e1", timestamp: "2026-01-01T00:00:00Z", description: "other" } as ForensicEvent,
      ],
    });
    const tags = (await request(app).get("/cases/c1/tags")).body;
    expect(tags[0].resolvedTargetId).toBeUndefined();
  });

  it("never sends the lineage itself to the dashboard", async () => {
    const { app, stateStore, first } = await harness();
    await foldIt(stateStore, first);
    expect((await stateStore.loadOverview("c1")).eventAliases).toEqual({ m1e1: "t2e5" });
    const state = (await request(app).get("/cases/c1/state")).body;
    expect(state.eventAliases).toBeUndefined();
  });
});
