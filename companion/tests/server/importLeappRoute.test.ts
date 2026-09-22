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
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";

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
  const analysisRunStore = new AnalysisRunStore(store, { appVersion: "test" });
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
    analysisRunStore,
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
    // #1132: the import's own sequence number, so a caller can bind this upload into a
    // mobile-backup-generation attestation without a separate lookup.
    expect(res.body.importSeq).toBe(1);

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
      expect(e.description).toMatch(
        /^iLEAPP Installed Apps \[origin: not established — leapp-origin-[\d-]+\]: /,
      );
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
    // The origin registry's coverage is in the activity line, the response and the timeline note (#988).
    expect(line).toContain("origin leapp-origin-");
    expect(line).toContain("2 not covered");
    expect(res.body.origin).toMatchObject({ schemaMatches: 0, notCovered: 2, headersDiffer: 0, excluded: 0 });
  });

  it("stamps the subject device the analyst named as the rows' asset, tags every row's origin, and writes the coverage into the timeline note and the run manifest (#988)", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();
    const safari = [
      "Visit Timestamp\tTitle\tURL\tVisit Count\tRedirect Source\tRedirect Destination\tVisit ID\tOrigin\tProfile",
      "2026-05-02 10:00:00\tt\thttps://a.example\t1\t\t\t1\tLocal Device\tDefault",
      "2026-05-02 10:00:01\tt\thttps://b.example\t1\t\t\t2\tiCloud Synced Device\tDefault",
    ].join("\n");
    const res = await request(app).post("/cases/c1/import-leapp").send({
      text: safari,
      filename: "Safari Browser - History.tsv",
      platform: "ios",
      device: "Ana's iPhone",
    });
    expect(res.status).toBe(202);
    expect(res.body.origin).toMatchObject({ schemaMatches: 2, notCovered: 0 });
    await waitForImportRecord(app, res.body.file as string);
    const state = await stateStore.load("c1");
    const rows = [
      ...state.forensicTimeline,
      ...(await superTimelineStore.query("c1", { limit: 50 })).events,
    ].filter((e) => e.description.includes("Safari Browser - History"));
    expect(rows.length).toBe(2);
    for (const e of rows) {
      expect(e.asset).toBe("Ana's iPhone");
      expect(e.description).toMatch(
        /\[origin: (recorded-on-this-device|synced-from-another-device), device-local, history — leapp-origin-[\d-]+\]/,
      );
      expect(e.canonical?.mobile?.registry.coverage).toBe("schema-matches");
    }
    expect(
      state.timeline.some(
        (t) =>
          t.description.includes("origin registry leapp-origin-") &&
          t.description.includes("2 row(s) covered"),
      ),
    ).toBe(true);
    const manifest = await pollFor("the run manifest with the origin coverage", async () => {
      const body = (await request(app).get("/cases/c1/analysis-runs")).body as unknown;
      const text = JSON.stringify(body);
      return text.includes("leappOrigin") ? text : undefined;
    });
    expect(manifest).toContain('"schemaMatches":2');
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

  it("reports a failed seam as a failed import instead of leaving Info rows in the forensic timeline", async () => {
    const { app, stateStore } = await makeApp();
    // Let the importer merge, then make the seam's first step fail: the reload of the merged state.
    const realLoad = stateStore.load.bind(stateStore);
    let loads = 0;
    // The snapshot (1st) and the importer's own load (2nd) succeed; the seam's reload (3rd) fails.
    stateStore.load = async (caseId: string) => {
      loads++;
      if (loads === 3) throw new Error("state store offline");
      return realLoad(caseId);
    };
    const res = await request(app)
      .post("/cases/c1/import-leapp")
      .send({ text: CALL_HISTORY, filename: "Call History.tsv", platform: "ios" });
    expect(res.status).toBe(202);
    const failure = await pollFor("the import to be recorded as failed", async () => {
      const diag = (await request(app).get("/diagnostics")).body as {
        report?: { importers?: { recentFailures?: Array<{ kind: string }> } };
      };
      return diag.report?.importers?.recentFailures?.find((f) => f.kind === "leapp");
    });
    expect(failure).toBeTruthy();
    // No import record was written for it.
    const meta = (await request(app).get("/cases/c1/import-meta")).body as { lastImportFile?: string };
    expect(meta.lastImportFile ?? "").not.toBe(res.body.file);
  });

  it("dual-writes both of two rows that differ only by letter case", async () => {
    // The import diff is case-folded; the seam selects added rows by id, so the second row is
    // dual-written and offered to the tagger rather than folded into the first.
    const { app } = await makeApp();
    const tsv = ["Name\tPath", "a\t/sdcard/Download/x", "a\t/sdcard/download/x"].join("\n");
    const res = await request(app).post("/cases/c1/import-leapp").send({ text: tsv, filename: "Files.tsv" });
    expect(res.status).toBe(202);
    const meta = (await waitForImportRecord(app, res.body.file as string)) as {
      superTimelineAddedCount: number;
    };
    expect(meta.superTimelineAddedCount).toBe(2);
    const st = (await request(app).get("/cases/c1/super-timeline")).body as {
      events: Array<{ description: string }>;
    };
    expect(st.events).toHaveLength(2);
  });

  it("never leaves a row in neither record when the super-timeline rejects the write", async () => {
    // The seam's own append is best-effort; demote captures what it removes and keeps the row in
    // the forensic timeline when that capture fails too. So a broken super-timeline store costs the
    // count, never the evidence.
    const { app, stateStore, superTimelineStore } = await makeApp();
    // Break `appendReporting`, not `append`: since #1535 the store has two entry points and
    // `append` is the thin wrapper that delegates to this one, so a fake outage installed on the
    // wrapper is simply not on the write path any more. Breaking the real one fails BOTH, which
    // is what a store that is genuinely offline does.
    superTimelineStore.appendReporting = async () => {
      throw new Error("super-timeline offline");
    };
    const res = await request(app)
      .post("/cases/c1/import-leapp")
      .send({ text: CALL_HISTORY, filename: "Call History.tsv", platform: "ios" });
    expect(res.status).toBe(202);
    const meta = (await waitForImportRecord(app, res.body.file as string)) as {
      superTimelineAddedCount: number;
    };
    expect(meta.superTimelineAddedCount).toBe(0);
    const forensic = (await stateStore.load("c1")).forensicTimeline;
    expect(forensic).toHaveLength(2); // still there — not demoted into nothing
    expect((await superTimelineStore.query("c1", {})).total).toBe(0);
  });

  it("refuses an export with no rows at all", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import-leapp")
      .send({ text: "Name\tValue\n", filename: "x.tsv" });
    expect(res.status).toBe(400);
  });
});
