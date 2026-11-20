import { describe, it, expect } from "vitest";
import type { Express } from "express";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #2619 — Undo an import, import the same file again: the forensic timeline holds the High row again
// under a NEW id, and the super-timeline row (content-deduped, old id) must be relinked to it so the
// raw record shows it as Promoted. A demoted Info row and a plain re-import must rewrite nothing.

const hit = (ts: string, level: string, image: string, eventId = 1) => ({
  group: "Sigma",
  kind: "individual",
  document: {
    kind: "evtx",
    path: "Sysmon.evtx",
    data: {
      Event: {
        System: {
          Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
          EventID: eventId,
          Channel: "Microsoft-Windows-Sysmon/Operational",
          Computer: "WIN-DC01.corp.local",
          TimeCreated: { "#attributes": { SystemTime: ts } },
        },
        EventData: {
          UtcTime: ts.replace("T", " ").replace("Z", ""),
          Image: image,
          CommandLine: `${image} -x`,
          ParentImage: "C:\\Windows\\explorer.exe",
        },
      },
    },
  },
  rule: { name: `Rule ${level}`, level, tags: ["attack.execution"] },
  timestamp: ts,
});

const FILE = {
  filename: "hunt.json",
  text: JSON.stringify([
    hit("2023-01-02T10:00:00.000Z", "high", "C:\\Users\\Public\\evil.exe"),
    hit("2023-01-02T10:05:00.000Z", "informational", "C:\\Windows\\System32\\notepad.exe", 5),
  ]),
};

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-undo-reimport-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const importUndoStore = new ImportUndoStore(store, 5);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  // The forensic gate is what demotes Info rows out of the forensic timeline (default floor: Low).
  const forensicGateControlStore = new ForensicGateControlStore(store);
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore,
    importUndoStore,
    superTimelineStore,
    forensicGateControlStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, superTimelineStore, importMetaStore };
}

async function settle(importMetaStore: ImportMetaStore, storedFile: string): Promise<void> {
  await pollFor(
    () => `import-meta to record '${storedFile}'`,
    async () => ((await importMetaStore.load("c1")).lastImportFile === storedFile ? true : undefined),
  );
  await new Promise((r) => setTimeout(r, 300));
}

async function startImport(app: Express): Promise<string> {
  const res = await request(app).post("/cases/c1/import").send(FILE);
  expect(res.status).toBe(202);
  return res.body.file as string;
}

interface Row {
  id: string;
  severity: string;
  promoted: boolean;
}
async function superRows(app: Express): Promise<Row[]> {
  const res = await request(app).get("/cases/c1/super-timeline?limit=100");
  expect(res.status).toBe(200);
  return res.body.events as Row[];
}

describe("#2619 — Undo + re-import re-links super-timeline rows to the forensic timeline", () => {
  it(
    "marks the re-imported row Promoted under its new id, keeps its tag, and leaves the demoted Info row alone",
    async () => {
      const { app, store, stateStore, superTimelineStore, importMetaStore } = await makeApp();
      await settle(importMetaStore, await startImport(app));
      const forensic1 = (await stateStore.load("c1")).forensicTimeline;
      expect(forensic1).toHaveLength(1);
      const highId1 = forensic1[0].id;
      const rows1 = await superRows(app);
      expect(rows1).toHaveLength(2);
      const infoId = rows1.find((r) => r.id !== highId1)!.id;
      await new TagsStore(store, superTimelineStore).add("c1", {
        targetType: "event",
        targetId: highId1,
        label: "analyst-note",
        author: "analyst",
      });

      expect((await request(app).post("/cases/c1/import/undo")).status).toBe(200);
      expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);

      await settle(importMetaStore, await startImport(app));
      const forensic2 = (await stateStore.load("c1")).forensicTimeline;
      expect(forensic2).toHaveLength(1);
      const highId2 = forensic2[0].id;
      expect(highId2).not.toBe(highId1);

      const rows2 = await superRows(app);
      expect(rows2).toHaveLength(2);
      const high = rows2.find((r) => r.id === highId2);
      expect(high).toMatchObject({ promoted: true, severity: forensic2[0].severity });
      const info = rows2.find((r) => r.id !== highId2)!;
      expect(info).toMatchObject({ id: infoId, promoted: false });
      const tags = await new TagsStore(store).load("c1");
      expect(tags.filter((t) => t.label === "analyst-note").map((t) => t.targetId)).toEqual([highId2]);

      // A plain re-import on top changes nothing in the raw record.
      const version = (await superTimelineStore.meta("c1")).version;
      await settle(importMetaStore, await startImport(app));
      expect((await superRows(app)).map((r) => r.id).sort()).toEqual(rows2.map((r) => r.id).sort());
      expect((await superTimelineStore.meta("c1")).version).toBe(version);
    },
    POLL_TIMEOUT_MS * 4,
  );
});
