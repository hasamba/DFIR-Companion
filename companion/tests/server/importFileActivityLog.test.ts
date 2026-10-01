import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { pollFor } from "../helpers/poll.js";

// #1906: an import by path (POST /cases/:id/import-file) settled and wrote its import-meta and undo
// level, but never its 'import' activity-log entry — the audit trail missed every such import. Both
// routes now write the same line.

const HUNT = [
  {
    group: "Sigma",
    kind: "individual",
    document: {
      kind: "evtx",
      path: "Sysmon.evtx",
      data: {
        Event: {
          System: {
            Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
            EventID: 1,
            Channel: "Microsoft-Windows-Sysmon/Operational",
            Computer: "wks-01.example.com",
            TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
          },
          EventData: { UtcTime: "2023-01-02 10:00:00.000", CommandLine: "whoami /all" },
        },
      },
    },
    rule: { name: "Suspicious Command", level: "high", tags: ["attack.execution"] },
    timestamp: "2023-01-02T10:00:00.000Z",
  },
];

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-ifact-")));
  const stateStore = new StateStore(store);
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
    superTimelineStore: new SuperTimelineStore(store),
    importMetaStore: new ImportMetaStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
    activityLogStore: new ActivityLogStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return app;
}

type Entry = { category?: string; action?: string; detail?: string };

async function importEntry(app: ReturnType<typeof createApp>, file: string): Promise<Entry> {
  return pollFor(`the import activity entry for ${file}`, async () => {
    const body = (await request(app).get("/cases/c1/activity-log")).body as unknown;
    if (!Array.isArray(body)) return undefined;
    return (body as Entry[]).find((e) => e.category === "import" && (e.detail ?? "").includes(file));
  });
}

describe("POST /cases/:id/import-file writes the 'import' activity entry (#1906)", () => {
  it("logs category 'import' with the same counts line as /import", async () => {
    const app = await makeApp();
    const src = join(await mkdtemp(join(tmpdir(), "dfir-ifact-src-")), "hunt.json");
    await writeFile(src, JSON.stringify(HUNT), "utf8");
    const res = await request(app).post("/cases/c1/import-file").send({ path: src });
    expect(res.status).toBe(202);
    const file = res.body.file as string;
    const entry = await importEntry(app, file);
    expect(entry.action).toBe("import");
    expect(entry.detail).toMatch(
      new RegExp(
        `^chainsaw \\(${file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\) — \\+1 event\\(s\\), \\+\\d+ IOC\\(s\\)$`,
      ),
    );

    // The pasted-text route writes the same shape.
    const pasted = await request(app)
      .post("/cases/c1/import")
      .send({ text: JSON.stringify(HUNT), filename: "hunt2.json" });
    expect(pasted.status).toBe(202);
    const other = await importEntry(app, pasted.body.file as string);
    expect(other.detail).toMatch(/^chainsaw \(.+\) — \+\d+ event\(s\), \+\d+ IOC\(s\)$/);
  });
});
