import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../src/storage/caseStore.js";
import { createApp } from "../src/server.js";
import { _resetDedupCache } from "../src/ingest/captureIngest.js";

let app: ReturnType<typeof createApp>;

async function pngBase64(): Promise<string> {
  const buf = await sharp({
    create: { width: 16, height: 16, channels: 3, background: { r: 10, g: 20, b: 30 } },
  }).png().toBuffer();
  return buf.toString("base64");
}

beforeEach(async () => {
  _resetDedupCache();
  const root = await mkdtemp(join(tmpdir(), "dfir-server-"));
  app = createApp(new CaseStore(root));
});

describe("HTTP server", () => {
  it("POST /cases creates a case", async () => {
    const res = await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "Incident A", investigator: "yaniv", aiProvider: null });
    expect(res.status).toBe(201);
    expect(res.body.caseId).toBe("c1");
  });

  it("POST /captures ingests a capture and returns metadata", async () => {
    await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app).post("/captures").send({
      caseId: "c1",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://velociraptor.local/hunts",
      tabTitle: "Hunts",
      triggerType: "timer",
      imageBase64: await pngBase64(),
    });
    expect(res.status).toBe(201);
    expect(res.body.sequenceNumber).toBe(1);
    expect(res.body.screenshotFile).toMatch(/\.webp$/);
  });

  it("POST /captures returns 400 on invalid payload", async () => {
    const res = await request(app).post("/captures").send({ caseId: "c1" });
    expect(res.status).toBe(400);
  });
});
