import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { _resetDedupCache } from "../../src/ingest/captureIngest.js";
import type { OcrRunner } from "../../src/analysis/ocrRedact.js";

// Stub OCR runner — "reads" a fixed line so the background-index path is exercised without tesseract.
const stubOcr: OcrRunner = {
  recognize: async () => [
    { text: "mimikatz.exe", bbox: { x: 0, y: 0, w: 60, h: 14 }, confidence: 95 },
    { text: "dumped", bbox: { x: 0, y: 0, w: 40, h: 14 }, confidence: 90 },
    { text: "creds", bbox: { x: 0, y: 0, w: 40, h: 14 }, confidence: 90 },
  ],
};

let app: ReturnType<typeof createApp>;
let cases: CaseStore;

beforeEach(async () => {
  // The suite defaults DFIR_OCR_SEARCH=off (see vitest.config.ts) so tests that don't care
  // about OCR never spin up real Tesseract; this file exercises the indexing path itself,
  // so it opts back in here (the one "off" test below overrides it again mid-test).
  process.env.DFIR_OCR_SEARCH = "on";
  _resetDedupCache();
  const root = await mkdtemp(join(tmpdir(), "dfir-ocrsearch-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { ocrRunner: stubOcr });
});

afterEach(() => {
  delete process.env.DFIR_OCR_SEARCH;
});

describe("GET /cases/:id/ocr-search", () => {
  beforeEach(async () => {
    await cases.putOcrEntry("c1", {
      screenshotFile: "000001_t.webp",
      text: "Running mimikatz dumped creds on VICTIM-PC",
      ocrAt: "2026-06-29T00:00:00.000Z",
      wordCount: 7,
    });
  });

  it("returns hits for a matching query", async () => {
    const res = await request(app).get("/cases/c1/ocr-search").query({ q: "mimikatz" });
    expect(res.status).toBe(200);
    expect(res.body.indexed).toBe(1);
    expect(res.body.hits).toHaveLength(1);
    expect(res.body.hits[0].screenshotFile).toBe("000001_t.webp");
    expect(res.body.hits[0].snippet).toContain("mimikatz");
  });

  it("400s on a blank query", async () => {
    const res = await request(app).get("/cases/c1/ocr-search").query({ q: "  " });
    expect(res.status).toBe(400);
  });

  it("404s for an unknown case", async () => {
    const res = await request(app).get("/cases/nope/ocr-search").query({ q: "mimikatz" });
    expect(res.status).toBe(404);
  });

  it("returns an empty hit list when nothing matches", async () => {
    const res = await request(app).get("/cases/c1/ocr-search").query({ q: "cobaltstrike" });
    expect(res.status).toBe(200);
    expect(res.body.hits).toEqual([]);
  });
});

describe("POST /captures background OCR indexing", () => {
  const capture = (over: Record<string, unknown> = {}) => ({
    caseId: "c1",
    timestamp: "2026-06-29T10:00:00.000Z",
    url: "https://host/console",
    tabTitle: "Console",
    triggerType: "navigation",
    imageBase64: Buffer.from([1, 2, 3, 4]).toString("base64"),
    ...over,
  });

  // The 201 returns before background OCR finishes; poll the index briefly.
  async function waitForIndex(file: string, tries = 40): Promise<boolean> {
    for (let i = 0; i < tries; i++) {
      const idx = await cases.loadOcrIndex("c1");
      if (idx[file]) return true;
      await new Promise((r) => setTimeout(r, 25));
    }
    return false;
  }

  it("indexes a captured screenshot's OCR text in the background", async () => {
    const res = await request(app).post("/captures").send(capture());
    expect(res.status).toBe(201);
    const file = res.body.screenshotFile as string;

    expect(await waitForIndex(file)).toBe(true);
    const idx = await cases.loadOcrIndex("c1");
    expect(idx[file].text).toBe("mimikatz.exe dumped creds");
    expect(idx[file].wordCount).toBe(3);

    // and it's searchable end-to-end
    const search = await request(app).get("/cases/c1/ocr-search").query({ q: "mimikatz" });
    expect(search.body.hits.map((h: { screenshotFile: string }) => h.screenshotFile)).toContain(file);
  });

  it("indexes EVERY screenshot in a burst (queued, not dropped past the concurrency cap)", async () => {
    // Seven captures posted back-to-back, each with distinct bytes so none is a byte-dup.
    const files: string[] = [];
    for (let i = 0; i < 7; i++) {
      const res = await request(app).post("/captures").send(capture({
        imageBase64: Buffer.from([i, i + 1, i + 2, i + 3]).toString("base64"),
      }));
      expect(res.status).toBe(201);
      files.push(res.body.screenshotFile as string);
    }
    // All seven must eventually be indexed — the queue drains them, none is dropped.
    for (const f of files) expect(await waitForIndex(f, 80)).toBe(true);
    expect(Object.keys(await cases.loadOcrIndex("c1"))).toHaveLength(7);
  });

  it("does not index when DFIR_OCR_SEARCH is off", async () => {
    process.env.DFIR_OCR_SEARCH = "off";
    const res = await request(app).post("/captures").send(capture());
    expect(res.status).toBe(201);
    // give the (disabled) path a moment — nothing should be written
    await new Promise((r) => setTimeout(r, 100));
    expect(await cases.loadOcrIndex("c1")).toEqual({});
  });
});
