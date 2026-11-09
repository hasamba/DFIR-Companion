// #2443: another analyst's close, reopen, archive or restore must reach every open dashboard live.
// The routes fire onCaseLifecycle only after the store change succeeded, never on a refusal, and
// the real wiring turns it into one BARE frame for every socket — no case id, no status, so a
// team-mode socket learns nothing about a case it cannot read.
import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createRuntimeStores } from "../../src/composition/runtimeStores.js";
import { buildAppOptions } from "../../src/composition/appWiring.js";
import type { SocketLike } from "../../src/live/hub.js";

const PASSWORD = "correct horse battery staple";
const roots: string[] = [];
afterAll(async () => {
  await Promise.all(roots.map((r) => rm(r, { recursive: true, force: true })));
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-lifecycle-push-"));
  roots.push(root);
  const store = new CaseStore(root);
  const fired: string[] = [];
  const app = createApp(store, {
    stateStore: new StateStore(store),
    onCaseLifecycle: (caseId: string) => fired.push(caseId),
  });
  const seed = (caseId: string) =>
    request(app)
      .post("/cases")
      .send({ caseId, name: caseId, investigator: "alice", aiProvider: "anthropic" });
  return { app, store, fired, seed };
}

describe("lifecycle routes fire onCaseLifecycle after a successful change (#2443)", () => {
  it("fires on close and again on reopen", async () => {
    const { app, fired, seed } = await harness();
    await seed("INC-1");
    expect((await request(app).patch("/cases/INC-1/status").send({ status: "closed" })).status).toBe(200);
    expect(fired).toEqual(["INC-1"]);
    expect((await request(app).patch("/cases/INC-1/status").send({ status: "open" })).status).toBe(200);
    expect(fired).toEqual(["INC-1", "INC-1"]);
  });

  it("does not fire when the status change is refused", async () => {
    const { app, fired, seed } = await harness();
    await seed("INC-2");
    await request(app).post("/cases/INC-2/archive").send({ removeFromList: true });
    fired.length = 0;
    const res = await request(app).patch("/cases/INC-2/status").send({ status: "open" });
    expect(res.status).toBe(409);
    expect((await request(app).patch("/cases/INC-2/status").send({ status: "bogus" })).status).toBe(400);
    expect(fired).toEqual([]);
  });

  it("fires on a ZIP archive that removes the case from the list, not on a plain archive", async () => {
    const { app, fired, seed } = await harness();
    await seed("INC-3");
    expect((await request(app).post("/cases/INC-3/archive").send({})).status).toBe(200);
    expect(fired).toEqual([]);
    const res = await request(app).post("/cases/INC-3/archive").send({ removeFromList: true });
    expect(res.body.removedFromList).toBe(true);
    expect(fired).toEqual(["INC-3"]);
  });

  it("fires on an encrypted export that removes the case from the list", async () => {
    const { app, fired, seed } = await harness();
    await seed("INC-4");
    const res = await request(app)
      .post("/cases/INC-4/export/encrypted")
      .send({ password: PASSWORD, removeFromList: true })
      .buffer()
      .parse((r, cb) => {
        r.on("data", () => {});
        r.on("end", () => cb(null, null));
      });
    expect(res.status).toBe(200);
    expect(fired).toEqual(["INC-4"]);
  });

  it("fires on restore, and not on a restore of a case that is not archived", async () => {
    const { app, fired, seed } = await harness();
    await seed("INC-5");
    expect((await request(app).post("/cases/INC-5/restore")).status).toBe(400);
    expect(fired).toEqual([]);
    await request(app).post("/cases/INC-5/archive").send({ removeFromList: true });
    fired.length = 0;
    expect((await request(app).post("/cases/INC-5/restore")).status).toBe(200);
    expect(fired).toEqual(["INC-5"]);
  });
});

describe("the real wiring sends one bare frame to every dashboard (#2443)", () => {
  function fakeSocket(): SocketLike & { sent: string[] } {
    const sent: string[] = [];
    return { sent, readyState: 1, OPEN: 1, send: (d: string) => sent.push(d) };
  }

  it("delivers exactly {type:'case_lifecycle_changed'} to sockets on other cases too", async () => {
    const base = await mkdtemp(join(tmpdir(), "dfir-lifecycle-wiring-"));
    roots.push(base);
    const casesRoot = join(base, "cases");
    await mkdir(casesRoot);
    const rt = createRuntimeStores({ casesRoot, host: "127.0.0.1", port: 0, logDir: join(base, "logs") });
    const options = buildAppOptions(rt, {} as Parameters<typeof buildAppOptions>[1]);
    const onA = fakeSocket();
    const onB = fakeSocket();
    rt.hub.subscribe("CASE-A", onA);
    rt.hub.subscribe("CASE-B", onB);
    options.onCaseLifecycle?.("CASE-A");
    for (const s of [onA, onB]) {
      expect(s.sent).toEqual([JSON.stringify({ type: "case_lifecycle_changed" })]);
      expect(s.sent[0]).not.toContain("CASE-A");
    }
  });
});
