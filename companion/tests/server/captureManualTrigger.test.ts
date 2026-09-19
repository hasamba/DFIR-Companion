import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { TRIGGER_TYPES } from "../../src/types.js";

// #1434: the extension's popup button and hotkey send `triggerType: "manual"`. The companion's
// payload schema stopped at `click`, so the capture came back 400 — which the extension's queue
// classifies as permanent and DROPS. An analyst's deliberate capture never reached the case.

let store: CaseStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  _resetDedupCache();
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-manual-trigger-")));
  app = createApp(store, { stateStore: new StateStore(store), commentsStore: new CommentsStore(store) });
  await store.createCase({ caseId: "c1", name: "Case", investigator: "alice", aiProvider: null });
});

async function png(): Promise<string> {
  const bytes = await sharp({ create: { width: 24, height: 24, channels: 3, background: "#3366aa" } })
    .png()
    .toBuffer();
  return bytes.toString("base64");
}

describe("POST /captures with the manual trigger", () => {
  it("accepts a popup/hotkey capture and records the trigger in the audit log", async () => {
    const res = await request(app)
      .post("/captures")
      .send({
        caseId: "c1",
        timestamp: "2026-09-19T10:00:00.000Z",
        url: "https://velociraptor.local/hunts",
        tabTitle: "Hunts",
        triggerType: "manual",
        imageBase64: await png(),
      });
    expect(res.status).toBe(201);
    expect(res.body.triggerType).toBe("manual");

    const log = await readFile(store.capturesLogPath("c1"), "utf8");
    const lines = log.split("\n").filter((l) => l.trim());
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).triggerType).toBe("manual");
  });

  it("still refuses a trigger neither side knows", async () => {
    const res = await request(app)
      .post("/captures")
      .send({
        caseId: "c1",
        timestamp: "2026-09-19T10:00:00.000Z",
        url: "https://velociraptor.local/hunts",
        tabTitle: "Hunts",
        triggerType: "telepathy",
        imageBase64: await png(),
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid payload");
  });
});

describe("trigger vocabulary contract", () => {
  it("the extension's TriggerType union and the companion's TRIGGER_TYPES are the same set", async () => {
    // The two lists are hand-maintained in two packages and drifted once (#1434). Read the
    // extension's union straight out of its source so the next drift fails here, not in the field.
    const src = await readFile(resolve(__dirname, "../../../extension/src/types.ts"), "utf8");
    const m = /export type TriggerType\s*=\s*([^;]+);/.exec(src);
    expect(m, "extension/src/types.ts must export `type TriggerType = ...`").toBeTruthy();
    const extension = [...m![1].matchAll(/"([a-z_]+)"/g)].map((x) => x[1]).sort();
    expect(extension).toEqual([...TRIGGER_TYPES].sort());
  });
});
