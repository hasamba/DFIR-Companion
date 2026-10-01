import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";

// #1902: parallel Mark False Positive / Unmark requests each did an unlocked load -> modify -> save of
// false-positive.json. Every request answered 200, but the last write won and silently dropped the
// other markers (15 parallel adds stored 3). Every accepted change must persist.
async function harness() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-fp-race-")));
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

const add = (app: Parameters<typeof request>[0], ref: string) =>
  request(app).post("/cases/c1/false-positive").send({ kind: "ioc", ref, reason: "known-good-tool" });

describe("false-positive routes under concurrency (#1902)", () => {
  it("keeps all 15 markers from 15 parallel adds", async () => {
    const { app, store } = await harness();
    const refs = Array.from({ length: 15 }, (_, i) => `10.0.0.${i + 1}`);
    const res = await Promise.all(refs.map((r) => add(app, r)));
    expect(res.every((r) => r.status === 200)).toBe(true);
    const stored = await new FalsePositiveStore(store).load("c1");
    expect(stored.map((m) => m.ref).sort()).toEqual([...refs].sort());
    expect((await request(app).get("/cases/c1/false-positive")).body).toHaveLength(15);
  });

  it("removes every marker on parallel removes", async () => {
    const { app, store } = await harness();
    const refs = Array.from({ length: 10 }, (_, i) => `10.0.1.${i + 1}`);
    await request(app)
      .post("/cases/c1/false-positive/batch")
      .send({ reason: "known-good-tool", items: refs.map((ref) => ({ kind: "ioc", ref })) });
    const ids = (await new FalsePositiveStore(store).load("c1")).map((m) => m.id);
    expect(ids).toHaveLength(10);
    const res = await Promise.all(
      ids.map((id) => request(app).post("/cases/c1/false-positive/remove").send({ id })),
    );
    expect(res.every((r) => r.status === 200)).toBe(true);
    expect(await new FalsePositiveStore(store).load("c1")).toEqual([]);
  });

  it("keeps the right set when adds, a batch and removes interleave", async () => {
    const { app, store } = await harness();
    await add(app, "keep-then-remove.example.com");
    const [removeId] = (await new FalsePositiveStore(store).load("c1")).map((m) => m.id);
    await Promise.all([
      add(app, "a.example.com"),
      request(app).post("/cases/c1/false-positive/remove").send({ id: removeId }),
      request(app)
        .post("/cases/c1/false-positive/batch")
        .send({ reason: "known-good-tool", items: [{ kind: "ioc", ref: "b.example.com" }] }),
      add(app, "c.example.com"),
    ]);
    const refs = (await new FalsePositiveStore(store).load("c1")).map((m) => m.ref).sort();
    expect(refs).toEqual(["a.example.com", "b.example.com", "c.example.com"]);
  });
});
