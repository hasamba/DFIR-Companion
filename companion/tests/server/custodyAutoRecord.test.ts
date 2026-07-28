import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;

async function pngBase64(): Promise<string> {
  const buf = await sharp({ create: { width: 8, height: 8, channels: 3, background: { r: 1, g: 2, b: 3 } } }).png().toBuffer();
  return buf.toString("base64");
}

beforeEach(async () => {
  _resetDedupCache();
  const root = await mkdtemp(join(tmpdir(), "dfir-custodyauto-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { custodyStore: new CustodyStore(cases) });
});

describe("automatic custody recording", () => {
  it("records custody for a screenshot the extension pushes, with no analyst action", async () => {
    const imageBase64 = await pngBase64();

    const post = await request(app).post("/captures").send({
      caseId: "c1",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://velociraptor.local/hunts",
      tabTitle: "Hunts",
      triggerType: "navigation",
      imageBase64,
    });
    expect(post.status).toBe(201);

    const { body } = await request(app).get("/cases/c1/custody");
    expect(body.records).toHaveLength(1);
    expect(body.records[0]).toMatchObject({
      caseId: "c1",
      sha256: createHash("sha256").update(Buffer.from(imageBase64, "base64")).digest("hex"),
      collectedBy: "browser-extension",
      source: "https://velociraptor.local/hunts",
      trigger: "navigation",
    });
    expect(body.records[0].artifactPath).toContain(cases.screenshotsDir("c1"));
    expect(body.records[0].collectedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("records custody for a stored import", async () => {
    const text = "ts,message\n2026-01-01T00:00:00Z,hello\n";

    const path = await cases.saveImport("c1", "0001_evidence.csv", text);

    const { body } = await request(app).get("/cases/c1/custody");
    expect(body.records).toHaveLength(1);
    expect(body.records[0]).toMatchObject({
      caseId: "c1",
      artifactPath: path,
      sha256: createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex"),
      collectedBy: "companion",
      trigger: "import",
    });
  });

  it("verifies clean, then flags the artifact once its bytes change on disk", async () => {
    const path = await cases.saveImport("c1", "0001_evidence.csv", "original\n");

    const clean = await request(app).get("/cases/c1/custody/verify");
    expect(clean.body).toMatchObject({ ok: true, mismatches: [] });

    await writeFile(path, "tampered\n", "utf8");

    const dirty = await request(app).get("/cases/c1/custody/verify");
    expect(dirty.body.ok).toBe(false);
    expect(dirty.body.mismatches).toHaveLength(1);
    expect(dirty.body.mismatches[0]).toMatchObject({ artifactPath: path, reason: "hash-mismatch" });
  });

  it("stores artifacts normally, and writes no custody log, when no custody store is configured", async () => {
    // A store of its own: the app in beforeEach already attached a listener to `cases`.
    const other = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-custodyauto-bare-")));
    await other.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    createApp(other, {});

    await expect(other.saveImport("c1", "0001_evidence.csv", "data")).resolves.toBeTruthy();

    await expect(readFile(join(other.metadataDir("c1"), "custody.jsonl"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });
});
