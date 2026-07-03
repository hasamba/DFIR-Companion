import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { IocWhitelistStore } from "../../src/analysis/iocWhitelistStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dfir-wl-"));
}

async function harness() {
  const root = await tmp();
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const legit = new FalsePositiveStore(store);
  const iocWhitelistStore = new IocWhitelistStore(join(root, "ioc-whitelist.json"));
  const app = createApp(store, { stateStore, iocWhitelistStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, legit, iocWhitelistStore };
}

describe("IOC whitelist CRUD routes", () => {
  it("starts empty, adds a rule, lists it, and deletes it", async () => {
    const { app } = await harness();
    expect((await request(app).get("/ioc-whitelist")).body).toEqual([]);

    const add = await request(app).post("/ioc-whitelist").send({ match: "cidr", pattern: "10.0.0.0/8", iocType: "ip", note: "internal" });
    expect(add.status).toBe(201);
    expect(add.body.id).toBeTruthy();
    expect(add.body).toMatchObject({ match: "cidr", pattern: "10.0.0.0/8", iocType: "ip", note: "internal" });

    const list = await request(app).get("/ioc-whitelist");
    expect(list.body).toHaveLength(1);

    const del = await request(app).delete(`/ioc-whitelist/${add.body.id}`);
    expect(del.status).toBe(200);
    expect((await request(app).get("/ioc-whitelist")).body).toEqual([]);
  });

  it("rejects an invalid rule (400) and a missing rule on delete (404)", async () => {
    const { app } = await harness();
    expect((await request(app).post("/ioc-whitelist").send({ match: "cidr", pattern: "not-a-cidr" })).status).toBe(400);
    expect((await request(app).post("/ioc-whitelist").send({ match: "bogus", pattern: "x" })).status).toBe(400);
    expect((await request(app).delete("/ioc-whitelist/ghost")).status).toBe(404);
  });

  it("is idempotent — re-adding the same rule does not duplicate", async () => {
    const { app } = await harness();
    const a = await request(app).post("/ioc-whitelist").send({ match: "exact", pattern: "deadbeef", iocType: "hash" });
    const b = await request(app).post("/ioc-whitelist").send({ match: "exact", pattern: "deadbeef", iocType: "hash" });
    expect(b.body.id).toBe(a.body.id);
    expect((await request(app).get("/ioc-whitelist")).body).toHaveLength(1);
  });

  it("returns 501 when no whitelist store is configured", async () => {
    const store = new CaseStore(await tmp());
    const app = createApp(store);
    expect((await request(app).post("/ioc-whitelist").send({ match: "exact", pattern: "x" })).status).toBe(501);
    expect((await request(app).get("/ioc-whitelist")).body).toEqual([]);   // GET degrades to empty
  });
});

describe("IOC whitelist import / export", () => {
  it("imports CSV, skips duplicates, and exports CSV + JSON", async () => {
    const { app } = await harness();
    const csv = "match,pattern,type,note\ncidr,10.0.0.0/8,ip,internal\nexact,deadbeef,hash,known good\nbad,x,,skip me\n";
    const imp = await request(app).post("/ioc-whitelist/import").send({ text: csv });
    expect(imp.status).toBe(200);
    expect(imp.body.added).toBe(2);     // the "bad" row is dropped
    expect(imp.body.total).toBe(2);

    // re-import is a no-op (dupes skipped)
    expect((await request(app).post("/ioc-whitelist/import").send({ text: csv })).body.added).toBe(0);

    const csvOut = await request(app).get("/ioc-whitelist/export?format=csv");
    expect(csvOut.headers["content-type"]).toContain("text/csv");
    expect(csvOut.text.split("\n")[0]).toBe("match,pattern,type,note");

    const jsonOut = await request(app).get("/ioc-whitelist/export");
    expect(JSON.parse(jsonOut.text)).toHaveLength(2);
  });

  it("400s on empty or unparseable import text", async () => {
    const { app } = await harness();
    expect((await request(app).post("/ioc-whitelist/import").send({ text: "" })).status).toBe(400);
    expect((await request(app).post("/ioc-whitelist/import").send({ text: "no,useful,columns\n1,2,3\n" })).status).toBe(400);
  });
});

describe("POST /cases/:id/ioc-whitelist/apply", () => {
  it("marks matching IOCs legitimate and leaves the rest", async () => {
    const { app, stateStore, legit } = await harness();
    await stateStore.save({
      ...emptyState("c1"),
      iocs: [
        { id: "i1", type: "ip", value: "10.1.2.3", firstSeen: "2026-01-01T00:00:00Z" },     // internal → whitelisted
        { id: "i2", type: "ip", value: "8.8.8.8", firstSeen: "2026-01-01T00:00:00Z" },       // public → kept
        { id: "i3", type: "hash", value: "deadbeef", firstSeen: "2026-01-01T00:00:00Z" },    // known-good hash → whitelisted
      ],
    });
    await request(app).post("/ioc-whitelist").send({ match: "cidr", pattern: "10.0.0.0/8", iocType: "ip", note: "internal" });
    await request(app).post("/ioc-whitelist").send({ match: "exact", pattern: "deadbeef", iocType: "hash" });

    const res = await request(app).post("/cases/c1/ioc-whitelist/apply");
    expect(res.status).toBe(200);
    expect(res.body.matched).toBe(2);
    expect(res.body.added).toBe(2);

    const markers = await legit.load("c1");
    const refs = markers.filter((m) => m.kind === "ioc").map((m) => m.ref).sort();
    expect(refs).toEqual(["10.1.2.3", "deadbeef"]);
    // 8.8.8.8 must NOT be marked legitimate
    expect(refs).not.toContain("8.8.8.8");

    // applying again adds nothing new (already marked)
    expect((await request(app).post("/cases/c1/ioc-whitelist/apply")).body.added).toBe(0);
  });

  it("adds nothing when the whitelist is empty", async () => {
    const { app, stateStore } = await harness();
    await stateStore.save({ ...emptyState("c1"), iocs: [{ id: "i1", type: "ip", value: "10.1.2.3", firstSeen: "2026-01-01T00:00:00Z" }] });
    const res = await request(app).post("/cases/c1/ioc-whitelist/apply");
    expect(res.status).toBe(200);
    expect(res.body.added).toBe(0);
  });
});
