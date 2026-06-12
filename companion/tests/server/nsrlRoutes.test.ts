import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { LegitimateStore } from "../../src/analysis/legitimate.js";
import { NsrlStore } from "../../src/analysis/nsrlStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const MD5 = "d41d8cd98f00b204e9800998ecf8427e";
const SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dfir-nsrl-"));
}

async function harness() {
  const root = await tmp();
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const legit = new LegitimateStore(store);
  const nsrlStore = new NsrlStore(join(root, "nsrl", "known-hashes.txt"));
  const app = createApp(store, { stateStore, nsrlStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, legit, nsrlStore };
}

describe("NSRL stats / import / clear / export routes", () => {
  it("starts empty, imports hashes, reports the count, exports, then clears", async () => {
    const { app } = await harness();
    expect((await request(app).get("/nsrl")).body).toEqual({ count: 0, enabled: false });

    const imp = await request(app).post("/nsrl/import").send({ text: `${MD5}\n${SHA256}\n${MD5}\n` });
    expect(imp.status).toBe(200);
    expect(imp.body).toMatchObject({ added: 2, total: 2 });

    expect((await request(app).get("/nsrl")).body).toEqual({ count: 2, enabled: true });

    // re-import is a no-op (dupes skipped)
    expect((await request(app).post("/nsrl/import").send({ text: MD5 })).body.added).toBe(0);

    const exp = await request(app).get("/nsrl/export");
    expect(exp.headers["content-type"]).toContain("text/plain");
    expect(exp.text.trim().split("\n").sort()).toEqual([MD5, SHA256].sort());

    expect((await request(app).post("/nsrl/clear")).body).toEqual({ cleared: true, count: 0 });
    expect((await request(app).get("/nsrl")).body.count).toBe(0);
  });

  it("400s on empty or hash-free import text", async () => {
    const { app } = await harness();
    expect((await request(app).post("/nsrl/import").send({ text: "" })).status).toBe(400);
    expect((await request(app).post("/nsrl/import").send({ text: "just words, no hashes" })).status).toBe(400);
  });

  it("returns 501 when no NSRL store is configured (GET degrades to disabled)", async () => {
    const app = createApp(new CaseStore(await tmp()));
    expect((await request(app).get("/nsrl")).body).toEqual({ count: 0, enabled: false });
    expect((await request(app).post("/nsrl/import").send({ text: MD5 })).status).toBe(501);
    expect((await request(app).post("/nsrl/clear")).status).toBe(501);
  });
});

describe("POST /cases/:id/nsrl/apply", () => {
  it("marks known-good IOCs and forensic events legitimate, leaving the rest", async () => {
    const { app, stateStore, legit } = await harness();
    const base = { description: "d", severity: "High" as const, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
    await stateStore.save({
      ...emptyState("c1"),
      iocs: [
        { id: "i1", type: "hash", value: MD5, firstSeen: "2026-01-01T00:00:00Z" },     // known-good → marked
        { id: "i2", type: "hash", value: "f".repeat(64), firstSeen: "2026-01-01T00:00:00Z" }, // unknown → kept
      ],
      forensicTimeline: [
        { id: "e1", timestamp: "2026-01-01T00:00:00Z", ...base, sha256: SHA256 },        // known-good file → marked
        { id: "e2", timestamp: "2026-01-01T00:00:00Z", ...base, sha256: "a".repeat(64) }, // unknown → kept
      ],
    });
    await request(app).post("/nsrl/import").send({ text: `${MD5}\n${SHA256}` });

    const res = await request(app).post("/cases/c1/nsrl/apply");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ matchedIocs: 1, matchedEvents: 1, added: 2 });

    const markers = await legit.load("c1");
    expect(markers.find((m) => m.kind === "ioc")?.ref).toBe(MD5);
    expect(markers.find((m) => m.kind === "event")?.ref).toBe("e1");

    // applying again adds nothing new (already marked)
    expect((await request(app).post("/cases/c1/nsrl/apply")).body.added).toBe(0);
  });

  it("adds nothing when the set is empty", async () => {
    const { app, stateStore } = await harness();
    await stateStore.save({ ...emptyState("c1"), iocs: [{ id: "i1", type: "hash", value: MD5, firstSeen: "2026-01-01T00:00:00Z" }] });
    const res = await request(app).post("/cases/c1/nsrl/apply");
    expect(res.status).toBe(200);
    expect(res.body.added).toBe(0);
  });
});
