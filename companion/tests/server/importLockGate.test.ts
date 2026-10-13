import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { MockProvider } from "../../src/providers/provider.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";

// Regression #2135: the case-lock gate exempted POST /cases/:id/import, so anyone who knew a locked
// case's id could add evidence to it with no cookie and no password. The REAL route via createApp —
// a refused import must leave no file in the case's imports folder and no line in its import log.

const PASSWORD = "secret123";
const CSV = "timestamp,message\n2023-01-02T10:00:00Z,encoded powershell from winword\n";

let store: CaseStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  resetLimiters();
  const root = await mkdtemp(join(tmpdir(), "dfir-import-lock-"));
  store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const canned = new MockProvider("mock", "{}");
  const pipeline = buildRuntimePipeline({
    provider: canned,
    synthesisProvider: canned,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await store.updateCaseMeta("c1", { password: await hashCasePassword(PASSWORD) });
});

async function importedFiles(): Promise<string[]> {
  return readdir(store.importsDir("c1")).catch(() => []);
}

async function importLog(): Promise<string> {
  return readFile(join(store.caseDir("c1"), "metadata", "imports.jsonl"), "utf8").catch(() => "");
}

describe("POST /cases/:id/import on a locked case (#2135)", () => {
  it("401s with no cookie and no password, and writes no evidence", async () => {
    const logBefore = await importLog();
    const res = await request(app).post("/cases/c1/import").send({ filename: "evil.csv", text: CSV });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("locked");
    expect(await importedFiles()).toEqual([]);
    expect(await importLog()).toBe(logBefore);
  });

  it("401s with a wrong password, and writes no evidence", async () => {
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "evil.csv", text: CSV, casePassword: "not-the-password" });
    expect(res.status).toBe(401);
    expect(await importedFiles()).toEqual([]);
  });

  it("accepts the right password, and the stored evidence does not contain it", async () => {
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "good.csv", text: CSV, casePassword: PASSWORD });
    expect(res.status).toBe(202);
    const files = await importedFiles();
    expect(files.length).toBe(1);
    const stored = await readFile(join(store.importsDir("c1"), files[0]), "utf8");
    expect(stored).not.toContain(PASSWORD);
    expect(await importLog()).not.toContain(PASSWORD);
  });
});
