import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";
import { ImportLock } from "../../src/analysis/importLock.js";

// #932 item 12. The dedicated LEAPP route used to call the importer and resynthesize — no lock, no
// dual-write, no tagger, no demote, no import record — so every LEAPP row (all Info) stayed in the
// forensic timeline the model reads and never reached the super-timeline. It now runs the same
// spine as the generic route, and a table with no time column is imported undated, not refused.

const INSTALLED_APPS = [
  "Name\tBundle ID\tSource",
  "Signal\torg.whispersystems.signal\tApp Store",
  "Unknown Sideload\tcom.example.invalid.app\thttps://lure.example.invalid/app.apk",
].join("\n");

const CALL_HISTORY = [
  "Timestamp\tNumber\tDirection",
  "2026-05-02 10:00:00\t+15550100\toutgoing",
  "\t+15550101\tmissed", // no clock on this row
].join("\n");

async function makeApp(opts: { importLock?: ImportLock } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-leapp-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  // Without the gate-control store demote is a no-op (composition/importIngest.ts), as it is in
  // every production wiring that has one.
  const forensicGateControlStore = new ForensicGateControlStore(store);
  const activityLogStore = new ActivityLogStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore,
    importMetaStore,
    forensicGateControlStore,
    activityLogStore,
    ...(opts.importLock ? { importLock: opts.importLock } : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore, importMetaStore };
}

async function waitForImportRecord(app: ReturnType<typeof createApp>, file: string) {
  return pollFor(`the LEAPP import ${file} to record its import-meta`, async () => {
    const meta = (await request(app).get("/cases/c1/import-meta")).body as { lastImportFile?: string };
    return meta.lastImportFile === file ? meta : undefined;
  });
}

describe("POST /cases/:id/import-leapp", () => {
  it("accepts a table with no time column and imports every row undated", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import-leapp")
      .send({ text: INSTALLED_APPS, filename: "Installed Apps.tsv", platform: "ios" });
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ accepted: true, events: 2, records: 2, undated: 2 });

    await waitForImportRecord(app, res.body.file as string);
    // Every row is Info: demoted out of the forensic timeline, present in the super-timeline.
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
    const st = (await request(app).get("/cases/c1/super-timeline")).body as {
      events: Array<{ timestamp: string; description: string; severity: string }>;
    };
    expect(st.events).toHaveLength(2);
    for (const e of st.events) {
      expect(e.timestamp).toBe("");
      expect(e.severity).toBe("Info");
      expect(e.description).toMatch(/^iLEAPP Installed Apps: /);
    }
    // The IOC the row carried survived the seam.
    expect((await stateStore.load("c1")).iocs.map((i) => i.value)).toContain("lure.example.invalid");
  });

  it("records the import like the generic route does, with the undated count in the activity line", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import-leapp")
      .send({ text: CALL_HISTORY, filename: "Call History.tsv", platform: "android" });
    expect(res.status).toBe(202);
    expect(res.body.undated).toBe(1);
    const meta = (await waitForImportRecord(app, res.body.file as string)) as {
      lastImportKind: string;
      superTimelineAddedCount: number;
      addedCount: number;
    };
    expect(meta.lastImportKind).toBe("leapp");
    expect(meta.superTimelineAddedCount).toBe(2);
    expect(meta.addedCount).toBe(0); // Info rows are not "+N events" — that count is graded signal
    // The activity line is written fire-and-forget after the import record, so poll for it.
    const line = await pollFor("the LEAPP activity line", async () => {
      const body = (await request(app).get("/cases/c1/activity-log")).body as unknown;
      if (!Array.isArray(body)) return undefined; // a transient non-200 while the import is still writing
      return (body as Array<{ detail?: string }>)
        .map((e) => e.detail ?? "")
        .find((d) => d.includes("leapp ("));
    });
    expect(line).toContain("1 undated");
  });

  it("lands the same split as the generic route for the same file", async () => {
    const { app, stateStore } = await makeApp();
    // The generic route reaches the LEAPP importer only when the name carries the tool's marker.
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ text: CALL_HISTORY, filename: "iLEAPP Call History.tsv" });
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("leapp");
    await waitForImportRecord(app, res.body.file as string);
    expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
    const st = (await request(app).get("/cases/c1/super-timeline")).body as {
      events: Array<{ timestamp: string }>;
    };
    expect(st.events.map((e) => e.timestamp === "")).toEqual([false, true]); // dated first, undated last
  });

  it(
    "waits for the import section like every other import writer",
    async () => {
      // Injecting the lock lets the test BE the import that is mid-section (importWriterExclusion).
      const importLock = new ImportLock();
      const { app, superTimelineStore } = await makeApp({ importLock });
      const rows = async (): Promise<number> => (await superTimelineStore.query("c1", {})).total;
      const send = (text: string, filename: string) =>
        request(app).post("/cases/c1/import-leapp").send({ text, filename, platform: "ios" });

      const startedAt = Date.now();
      expect((await send(CALL_HISTORY, "Call History.tsv")).status).toBe(202);
      await pollFor("the first LEAPP import to land", async () => ((await rows()) === 2 ? true : undefined));
      const unblockedMs = Date.now() - startedAt;

      const release = await importLock.acquire("c1");
      expect((await send(INSTALLED_APPS, "Installed Apps.tsv")).status).toBe(202);
      await new Promise((r) => setTimeout(r, Math.max(250, unblockedMs * 5)));
      expect(await rows()).toBe(2); // held back: nothing of the second import has landed

      release();
      await pollFor("the second LEAPP import to land once the section is free", async () =>
        (await rows()) === 4 ? true : undefined,
      );
    },
    POLL_TIMEOUT_MS * 3,
  );

  it("refuses an export with no rows at all", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import-leapp")
      .send({ text: "Name\tValue\n", filename: "x.tsv" });
    expect(res.status).toBe(400);
  });
});
