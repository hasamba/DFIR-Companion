import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, readdir, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { ingestCapture, _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { _resetReplayIndex } from "../../src/ingest/captureReplay.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// #2397: the extension re-sends a screenshot after any ambiguous failure, and after a worker
// suspend between the companion's 201 and the queue row's removal. Each screenshot carries a random
// captureId; a genuine re-send must not become a second copy of the same evidence.

let root: string;
let store: CaseStore;

async function png(r: number): Promise<string> {
  const buf = await sharp({ create: { width: 16, height: 16, channels: 3, background: { r, g: 10, b: 20 } } })
    .png()
    .toBuffer();
  return buf.toString("base64");
}

function body(over: Record<string, unknown> = {}) {
  return {
    caseId: "c1",
    timestamp: "2026-11-08T10:00:00.000Z",
    url: "https://example.test/hunts",
    tabTitle: "Hunts",
    triggerType: "timer",
    imageBase64: "",
    captureId: "0b6f3d6e-6a58-4c4e-9d2f-2f1d0c7a9e11",
    ...over,
  };
}

async function logLines(): Promise<unknown[]> {
  const raw = await readFile(store.capturesLogPath("c1"), "utf8");
  return raw
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
}

beforeEach(async () => {
  _resetDedupCache();
  resetLimiters();
  root = await mkdtemp(join(tmpdir(), "dfir-replay-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
});

describe("ingestCapture — re-sent captures (#2397)", () => {
  it("answers a re-send with the stored record and writes nothing new", async () => {
    const img = await png(1);
    const first = await ingestCapture(store, body({ imageBase64: img }));
    const again = await ingestCapture(store, body({ imageBase64: img }));
    expect(first.captureId).toBe(body().captureId);
    expect(first.replayed).toBeUndefined();
    expect(again).toMatchObject({
      replayed: true,
      sequenceNumber: first.sequenceNumber,
      screenshotFile: first.screenshotFile,
    });
    expect(await logLines()).toHaveLength(1);
    expect(await readdir(store.screenshotsDir("c1"))).toHaveLength(1);
  });

  it("never writes `replayed` into the capture log", async () => {
    const img = await png(1);
    await ingestCapture(store, body({ imageBase64: img }));
    await ingestCapture(store, body({ imageBase64: img }));
    expect(JSON.stringify(await logLines())).not.toContain("replayed");
  });

  it("recognises a re-send after a restart, from the capture log", async () => {
    const img = await png(1);
    await ingestCapture(store, body({ imageBase64: img }));
    _resetDedupCache(); // the process restarted: every in-memory index is gone
    const again = await ingestCapture(store, body({ imageBase64: img }));
    expect(again.replayed).toBe(true);
    expect(await logLines()).toHaveLength(1);
  });

  it("two identical re-sends arriving together still store one capture", async () => {
    const img = await png(1);
    const results = await Promise.all([1, 2, 3].map(() => ingestCapture(store, body({ imageBase64: img }))));
    expect(results.filter((r) => !r.replayed)).toHaveLength(1);
    expect(await logLines()).toHaveLength(1);
  });

  it("stores different bytes under a reused id as new evidence, and recognises each later", async () => {
    const a = await png(1);
    const b = await png(200);
    await ingestCapture(store, body({ imageBase64: a }));
    const second = await ingestCapture(store, body({ imageBase64: b }));
    expect(second.replayed).toBeUndefined();
    _resetReplayIndex();
    expect((await ingestCapture(store, body({ imageBase64: a }))).replayed).toBe(true);
    expect((await ingestCapture(store, body({ imageBase64: b }))).replayed).toBe(true);
    expect(await logLines()).toHaveLength(2);
  });

  it("treats the same id and image with different capture details as a new capture", async () => {
    const img = await png(1);
    await ingestCapture(store, body({ imageBase64: img }));
    const other = await ingestCapture(store, body({ imageBase64: img, url: "https://example.test/other" }));
    expect(other.replayed).toBeUndefined();
    expect(await logLines()).toHaveLength(2);
  });

  it("stores every capture without an id, as before", async () => {
    const img = await png(1);
    await ingestCapture(store, body({ imageBase64: img, captureId: undefined }));
    const second = await ingestCapture(store, body({ imageBase64: img, captureId: undefined }));
    expect(second.replayed).toBeUndefined();
    expect(second.isDuplicate).toBe(true);
    expect(await logLines()).toHaveLength(2);
  });

  it("refuses a malformed id", async () => {
    await expect(
      ingestCapture(store, body({ imageBase64: await png(1), captureId: "../x" })),
    ).rejects.toThrow();
  });

  it("does not trust an index built past a damaged log line", async () => {
    const img = await png(1);
    await ingestCapture(store, body({ imageBase64: img }));
    await appendFile(store.capturesLogPath("c1"), "{not json\n", "utf8");
    _resetReplayIndex();
    // Fail safe: an index built past the damage is not trusted, so the capture is stored again
    // rather than answered from a possibly incomplete record (a restart then refuses the damaged
    // log outright, via the sequence allocator).
    const again = await ingestCapture(store, body({ imageBase64: img }));
    expect(again.replayed).toBeUndefined();
  });
});

describe("POST /captures — re-sent captures (#2397)", () => {
  it("answers 201 with the stored record, marked as a re-send", async () => {
    const app = createApp(store, {});
    const payload = body({ imageBase64: await png(1) });
    const first = await request(app).post("/captures").send(payload);
    const again = await request(app).post("/captures").send(payload);
    expect(first.status).toBe(201);
    expect(again.status).toBe(201);
    expect(again.body).toMatchObject({ replayed: true, sequenceNumber: first.body.sequenceNumber });
    expect(again.body.analyzed).toBeUndefined();
    expect(await logLines()).toHaveLength(1);
  });
});

describe("POST /captures — which limit a 429 hit (#2397)", () => {
  it("labels a per-case password lockout so the extension can keep other cases moving", async () => {
    const app = createApp(store, {});
    await store.updateCaseMeta("c1", { password: await hashCasePassword("secret123") });
    let last: request.Response | undefined;
    for (let i = 0; i < 7; i++) {
      last = await request(app)
        .post("/captures")
        .send({ ...body({ imageBase64: await png(1) }), casePassword: `wrong${i}` });
      if (last.status === 429) break;
    }
    expect(last?.status).toBe(429);
    expect(last?.body.code).toBe("case-password-lockout");
  });
});
