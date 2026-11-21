import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { getServerLogger } from "../../src/logging/serverLogger.js";
import { StateFileCorruptError } from "../../src/storage/stateFileCorrupt.js";

// #2783: a damaged investigation.json or case SQLite store answered GET /cases/:id/state with the
// bare parser/sqlite text, naming neither the case nor the file.

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-state-corrupt-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "INC-1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore });
  const stateDir = store.stateDir("INC-1");
  await mkdir(stateDir, { recursive: true });
  return { app, store, stateStore, stateDir };
}

afterEach(() => vi.restoreAllMocks());

describe("GET /cases/:id/state on a damaged case (#2783)", () => {
  it("a truncated investigation.json names the case and the file, with no parser text", async () => {
    const { app, stateDir } = await harness();
    await writeFile(join(stateDir, "investigation.json"), '{"caseId":"INC-1","findings":[', "utf8");
    const warn = vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});

    const res = await request(app).get("/cases/INC-1/state");

    expect(res.status).toBe(409);
    expect(res.body.code).toBe("state_file_corrupt");
    expect(res.body.file).toBe("investigation.json");
    expect(res.body.error).toContain("INC-1");
    expect(res.body.error).toContain("state/investigation.json");
    expect(JSON.stringify(res.body)).not.toMatch(/Unexpected|JSON input|position/i);
    // The raw parser text is kept for the server log.
    expect(warn.mock.calls.map((c) => String(c[0])).join("\n")).toMatch(/INC-1.*investigation\.json/);
  });

  it("a damaged SQLite store names the case and the file, with no sqlite text", async () => {
    const { app, stateDir } = await harness();
    await writeFile(
      join(stateDir, "investigation.sqlite"),
      "this is not a sqlite database at all".repeat(200),
    );
    vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});

    const res = await request(app).get("/cases/INC-1/state");

    expect(res.status).toBe(409);
    expect(res.body.code).toBe("state_file_corrupt");
    expect(res.body.file).toBe("investigation.sqlite");
    expect(res.body.error).toContain("INC-1");
    expect(JSON.stringify(res.body)).not.toMatch(/file is not a database|malformed|SQLITE_|ERR_SQLITE/i);
  });

  it("StateStore.load throws StateFileCorruptError for a truncated legacy file", async () => {
    const { stateStore, stateDir } = await harness();
    await writeFile(join(stateDir, "investigation.json"), "{", "utf8");
    vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});
    await expect(stateStore.load("INC-1")).rejects.toBeInstanceOf(StateFileCorruptError);
  });

  it("a store whose pages are damaged after the header names the file, with no sqlite text", async () => {
    const { app, stateStore, stateDir } = await harness();
    await stateStore.save({ ...emptyState("INC-1"), lastSummary: "x".repeat(200_000) });
    const dbPath = join(stateDir, "investigation.sqlite");
    // Fold the WAL into the main file, then overwrite every page after the first.
    await caseSqliteWorker.request({ op: "backupDatabase", dbPath, targetPath: dbPath + ".bak" });
    const bytes = await readFile(dbPath + ".bak");
    await rm(dbPath + "-wal", { force: true });
    await rm(dbPath + "-shm", { force: true });
    await writeFile(
      dbPath,
      Buffer.concat([bytes.subarray(0, 4096), Buffer.alloc(bytes.length - 4096, 0x5a)]),
    );
    vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});

    const res = await request(app).get("/cases/INC-1/state");

    expect(res.status).toBe(409);
    expect(res.body.file).toBe("investigation.sqlite");
    expect(JSON.stringify(res.body)).not.toMatch(/file is not a database|malformed|SQLITE_|ERR_SQLITE/i);
  });

  it("one damaged case does not break the case list or a healthy case beside it", async () => {
    const { app, stateDir, store } = await harness();
    await writeFile(join(stateDir, "investigation.json"), "{", "utf8");
    await store.createCase({ caseId: "INC-2", name: "n", investigator: "i", aiProvider: null });
    await new StateStore(store).save({ ...emptyState("INC-2"), lastSummary: "healthy" });
    vi.spyOn(getServerLogger(), "warn").mockImplementation(() => {});

    expect((await request(app).get("/cases")).status).toBe(200);
    const healthy = await request(app).get("/cases/INC-2/state");
    expect(healthy.status).toBe(200);
    expect(healthy.body.lastSummary).toBe("healthy");
  });

  it("a healthy case still loads", async () => {
    const { app, stateStore } = await harness();
    await stateStore.save({ ...emptyState("INC-1"), lastSummary: "healthy" });
    const res = await request(app).get("/cases/INC-1/state");
    expect(res.status).toBe(200);
    expect(res.body.lastSummary).toBe("healthy");
  });
});
