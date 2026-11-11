// #2560: AWS account weaknesses through the real pipeline (whole-file and streamed imports) and the
// two read routes. The streamed import runs in several batches; a re-import changes no count.
import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CloudWeaknessStore } from "../../src/analysis/cloudWeaknessStore.js";
import { sans504Upload, TARGET_BUCKET } from "../analysis/fixtures/sans504Lab.js";

const KINDS = ["root-no-mfa-login", "root-routine-use", "object-lock-missing", "object-logging-window"];

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cw-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: false });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, pipeline, root };
}

describe("AWS account weaknesses routes (#2560)", () => {
  it("a fresh case has no list yet, and an empty CSV with its header", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/cloud-weaknesses");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ read: false, items: [] });
    expect(res.body.limits.length).toBeGreaterThan(0);
    const csv = await request(app).get("/cases/c1/cloud-weaknesses.csv");
    expect(csv.status).toBe(200);
    expect(csv.headers["content-type"]).toMatch(/text\/csv/);
    expect(csv.text.trim()).toBe(
      '"kind","title","account","bucket","detail","record_role","event_id","event_time"',
    );
  });

  it("a whole-file CloudTrail import records the lab's four weaknesses; importing it again changes nothing", async () => {
    const { app, store, pipeline } = await makeApp();
    const opts = (n: number) => ({
      label: `lab-${n}.json`,
      idPrefix: `a${n}`,
      importedAt: "2026-11-11T00:00:00Z",
    });
    await pipeline.importAws("c1", sans504Upload(), opts(1));
    const first = await new CloudWeaknessStore(store).load("c1");
    const res = await request(app).get("/cases/c1/cloud-weaknesses");
    expect(res.body.read).toBe(true);
    expect(res.body.items.map((i: { kind: string }) => i.kind)).toEqual(KINDS);
    await pipeline.importAws("c1", sans504Upload(), opts(2));
    expect(await new CloudWeaknessStore(store).load("c1")).toEqual(first);
    const csv = await request(app).get("/cases/c1/cloud-weaknesses.csv");
    expect(csv.text).toContain(`"${TARGET_BUCKET}"`);
  });

  it("a streamed import in many batches records the same list as the whole-file import", async () => {
    const whole = await makeApp();
    await whole.pipeline.importAws("c1", sans504Upload(), {
      label: "lab.json",
      idPrefix: "a1",
      importedAt: "2026-11-11T00:00:00Z",
    });
    const streamed = await makeApp();
    const path = join(streamed.root, "lab-upload.json");
    await writeFile(path, sans504Upload());
    await streamed.pipeline.importCloudFile("c1", "aws", path, {
      label: "lab.json",
      idPrefix: "s1",
      importedAt: "2026-11-11T00:00:00Z",
      batchRecords: 7,
    });
    const fromStream = await new CloudWeaknessStore(streamed.store).load("c1");
    expect(fromStream?.accounts.length).toBeGreaterThan(0);
    expect(fromStream).toEqual(await new CloudWeaknessStore(whole.store).load("c1"));
  });
});
