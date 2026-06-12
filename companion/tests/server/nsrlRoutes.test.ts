import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { LegitimateStore } from "../../src/analysis/legitimate.js";
import { NsrlStore } from "../../src/analysis/nsrlStore.js";
import { NsrlDb } from "../../src/analysis/nsrlDb.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

const DatabaseSync = loadDatabaseSync();

// Build a tiny NSRL-RDS-shaped SQLite file (METADATA base table + FILE view, uppercase hashes).
async function buildRds(dir: string, rows: Array<{ sha256?: string; md5?: string }>): Promise<string> {
  const file = join(dir, "rds.db");
  const db = new DatabaseSync(file);
  db.exec("CREATE TABLE METADATA(package_id INTEGER, sha256 TEXT, sha1 TEXT, md5 TEXT, file_name TEXT)");
  db.exec("CREATE VIEW FILE AS SELECT * FROM METADATA");
  const ins = db.prepare("INSERT INTO METADATA(sha256, md5) VALUES(?, ?)");
  for (const r of rows) ins.run(r.sha256?.toUpperCase() ?? null, r.md5?.toUpperCase() ?? null);
  db.close();
  return file;
}

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
    expect((await request(app).get("/nsrl")).body).toMatchObject({ count: 0, enabled: false, db: { connected: false } });

    const imp = await request(app).post("/nsrl/import").send({ text: `${MD5}\n${SHA256}\n${MD5}\n` });
    expect(imp.status).toBe(200);
    expect(imp.body).toMatchObject({ added: 2, total: 2 });

    expect((await request(app).get("/nsrl")).body).toMatchObject({ count: 2, enabled: true });

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
    expect((await request(app).get("/nsrl")).body).toMatchObject({ count: 0, enabled: false, db: { connected: false } });
    expect((await request(app).post("/nsrl/import").send({ text: MD5 })).status).toBe(501);
    expect((await request(app).post("/nsrl/import-file").send({ path: "x" })).status).toBe(501);
    expect((await request(app).post("/nsrl/clear")).status).toBe(501);
  });
});

describe("POST /nsrl/import-file", () => {
  it("loads hashes from a file path, reporting per-file results", async () => {
    const { app } = await harness();
    const dir = await tmp();
    const file = join(dir, "rds.txt");
    await writeFile(file, `${MD5}\n${SHA256}\n`, "utf8");

    const res = await request(app).post("/nsrl/import-file").send({ path: file });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ added: 2, total: 2 });
    expect(res.body.files).toHaveLength(1);
    expect(res.body.files[0]).toMatchObject({ file, added: 2 });
    expect((await request(app).get("/nsrl")).body.count).toBe(2);
  });

  it("is best-effort per file — one good + one missing path → 200 with mixed results", async () => {
    const { app } = await harness();
    const dir = await tmp();
    const good = join(dir, "good.txt");
    await writeFile(good, MD5, "utf8");
    const res = await request(app).post("/nsrl/import-file").send({ path: `${good} ; ${join(dir, "nope.txt")}` });
    expect(res.status).toBe(200);
    expect(res.body.added).toBe(1);
    expect(res.body.files.filter((f: { error?: string }) => f.error)).toHaveLength(1);
  });

  it("400s when no path is given, or every path fails", async () => {
    const { app } = await harness();
    expect((await request(app).post("/nsrl/import-file").send({})).status).toBe(400);
    const res = await request(app).post("/nsrl/import-file").send({ path: join(await tmp(), "ghost.txt") });
    expect(res.status).toBe(400);   // all paths failed → nothing loaded
    expect(res.body.files[0].error).toBeTruthy();
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

describe("NSRL RDS SQLite backend (#63)", () => {
  it("connects a DB, reports status, matches events by it, then disconnects", async () => {
    const root = await tmp();
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const legit = new LegitimateStore(store);
    const dbFile = await buildRds(root, [{ sha256: SHA256 }]);   // one known-good sha256
    const app = createApp(store, { stateStore, nsrlDbConfigFile: join(root, "nsrl", "db-path.txt") });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    // not connected yet
    expect((await request(app).get("/nsrl")).body).toMatchObject({ db: { connected: false }, dbConfigurable: true });

    const conn = await request(app).post("/nsrl/db").send({ path: dbFile });
    expect(conn.status).toBe(200);
    expect(conn.body).toMatchObject({ connected: true, table: "METADATA" });
    expect(conn.body.columns).toContain("sha256");
    expect((await request(app).get("/nsrl")).body.db).toMatchObject({ connected: true, table: "METADATA" });

    // an event carrying that sha256 is auto-marked legitimate by the DB lookup
    const base = { description: "d", severity: "High" as const, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
    await stateStore.save({
      ...emptyState("c1"),
      forensicTimeline: [
        { id: "e1", timestamp: "2026-01-01T00:00:00Z", ...base, sha256: SHA256.toUpperCase() }, // known-good (case-insensitive)
        { id: "e2", timestamp: "2026-01-01T00:00:00Z", ...base, sha256: "f".repeat(64) },        // unknown
      ],
    });
    const applied = await request(app).post("/cases/c1/nsrl/apply");
    expect(applied.body).toMatchObject({ matchedEvents: 1, added: 1 });
    expect((await legit.load("c1")).find((m) => m.kind === "event")?.ref).toBe("e1");

    const disc = await request(app).delete("/nsrl/db");
    expect(disc.status).toBe(200);
    expect((await request(app).get("/nsrl")).body.db).toEqual({ connected: false });
  });

  it("400s on a bad DB path and when the path is missing", async () => {
    const root = await tmp();
    const app = createApp(new CaseStore(root), { nsrlDbConfigFile: join(root, "nsrl", "db-path.txt") });
    expect((await request(app).post("/nsrl/db").send({})).status).toBe(400);                 // no path
    expect((await request(app).post("/nsrl/db").send({ path: join(root, "ghost.db") })).status).toBe(400); // unopenable
  });

  it("rejects connect/disconnect when the path is env-managed", async () => {
    const root = await tmp();
    const app = createApp(new CaseStore(root), { nsrlDbConfigFile: join(root, "nsrl", "db-path.txt"), nsrlDbEnvManaged: true });
    expect((await request(app).get("/nsrl")).body).toMatchObject({ dbEnvManaged: true, dbConfigurable: false });
    expect((await request(app).post("/nsrl/db").send({ path: "x" })).status).toBe(400);
    expect((await request(app).delete("/nsrl/db")).status).toBe(400);
  });

  it("501s on db routes when no config file is wired", async () => {
    const app = createApp(new CaseStore(await tmp()), {});
    expect((await request(app).post("/nsrl/db").send({ path: "x" })).status).toBe(501);
    expect((await request(app).delete("/nsrl/db")).status).toBe(501);
  });
});
