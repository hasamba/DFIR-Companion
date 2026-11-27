import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CustodyStore, type CustodyRecord } from "../../src/analysis/custody.js";

/**
 * #3022: the seeded demo case claims five screenshot captures and four imports, so its Chain of
 * Custody must show them — stored files with hashes, and the events that touched them — and
 * "Verify now" must pass on it.
 */
async function harness(opts: { demoMode?: boolean; custody?: CustodyStore | "failing" } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-seed-custody-"));
  const store = new CaseStore(root);
  const custodyStore =
    opts.custody === "failing"
      ? (Object.assign(Object.create(CustodyStore.prototype), {
          recordMany: async () => {
            throw new Error("disk full");
          },
          load: async () => [],
        }) as CustodyStore)
      : (opts.custody ?? new CustodyStore(store));
  const app = createApp(store, { stateStore: new StateStore(store), demoMode: opts.demoMode, custodyStore });
  return { app, store, root };
}

async function custodyOf(app: ReturnType<typeof createApp>, caseId: string): Promise<CustodyRecord[]> {
  const res = await request(app).get(`/cases/${caseId}/custody`);
  expect(res.status).toBe(200);
  return res.body.records as CustodyRecord[];
}

async function expectVerified(app: ReturnType<typeof createApp>, caseId: string): Promise<void> {
  const res = await request(app).get(`/cases/${caseId}/custody/verify`);
  expect(res.status).toBe(200);
  expect(res.body).toEqual({ ok: true, mismatches: [], chainBreaks: [] });
}

const jsonlRows = async (path: string) =>
  (await readFile(path, "utf8"))
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);

describe("seeded demo case chain of custody (#3022)", () => {
  it("records every capture and import the demo claims, and verifies clean", async () => {
    const { app, root } = await harness();
    const seeded = await request(app).post("/cases/seed-demo").send({});
    expect(seeded.status).toBe(201);
    expect(seeded.body.custody).toBeUndefined(); // internal, never in the response
    expect(seeded.body.custodyError).toBeUndefined();

    const caseDir = join(root, "demo");
    const captures = await jsonlRows(join(caseDir, "metadata", "captures.jsonl"));
    const imports = await jsonlRows(join(caseDir, "metadata", "imports.jsonl"));
    expect(captures).toHaveLength(5);
    expect(imports).toHaveLength(4);

    const records = await custodyOf(app, "demo");
    const collected = records.filter((r) => r.event === "collected");
    const received = records.filter((r) => r.event === "received");
    expect(collected).toHaveLength(9);
    expect(received).toHaveLength(4);

    for (const c of captures) {
      const path = join(caseDir, "screenshots", String(c.screenshotFile));
      const rec = collected.find((r) => r.artifactPath === path);
      expect(rec, path).toBeDefined();
      expect(rec!.source).toBe(c.url);
      expect(rec!.collectedAt).toBe(c.timestamp);
      const meta = await sharp(path).metadata(); // a real, decodable image
      expect(meta.format).toBe("webp");
    }
    expect(new Set(collected.map((r) => r.sha256)).size).toBe(9);

    for (const i of imports) {
      const path = join(caseDir, "imports", String(i.filename));
      expect(
        collected.find((r) => r.artifactPath === path),
        path,
      ).toBeDefined();
      expect((await stat(path)).size).toBe(i.bytes); // the list matches the stored file
      const receipt = received.find((r) => r.source === i.originalName);
      expect(receipt?.bytes).toBe(i.bytes);
    }

    // One chain in time order: seq strictly increasing, timestamps never going backwards.
    const times = records.map((r) => r.collectedAt);
    expect([...times].sort()).toEqual(times);
    await expectVerified(app, "demo");
  });

  it("a force reseed starts a fresh chain rather than appending to the old one", async () => {
    const { app } = await harness();
    expect((await request(app).post("/cases/seed-demo").send({})).status).toBe(201);
    expect((await request(app).patch("/cases/demo/status").send({ status: "closed" })).status).toBe(200);
    const reseeded = await request(app).post("/cases/seed-demo").send({ caseId: "demo", force: true });
    expect(reseeded.status).toBe(201);
    expect(await custodyOf(app, "demo")).toHaveLength(13);
    await expectVerified(app, "demo");
  });

  it("overlapping demo-mode reseeds leave one trail, not a doubled one", async () => {
    const { app } = await harness({ demoMode: true });
    const results = await Promise.all(
      [0, 1, 2].map(() => request(app).post("/cases/seed-demo").send({ force: true })),
    );
    for (const r of results) expect([201, 409]).toContain(r.status);
    expect(results.some((r) => r.status === 201)).toBe(true);
    expect(await custodyOf(app, "demo")).toHaveLength(13);
    await expectVerified(app, "demo");
  });

  it("records custody under a custom case id", async () => {
    const { app } = await harness();
    expect((await request(app).post("/cases/seed-demo").send({ caseId: "demo-two" })).status).toBe(201);
    expect(await custodyOf(app, "demo-two")).toHaveLength(13);
    await expectVerified(app, "demo-two");
  });

  it("a custody failure does not fail the seed", async () => {
    const { app } = await harness({ custody: "failing" });
    const res = await request(app).post("/cases/seed-demo").send({});
    expect(res.status).toBe(201);
    expect(res.body.custodyError).toContain("disk full");
    const ids = (await request(app).get("/cases")).body.map((c: { caseId: string }) => c.caseId);
    expect(ids).toContain("demo");
  });
});
