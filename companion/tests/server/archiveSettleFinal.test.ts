// #2801: a case folder that changes during every archive attempt — the last included — must fail the
// ZIP delete with the retryable 503 and leave the case on disk. The final attempt used to skip its
// verification re-walk and return an archive missing the newest file, and the case was then deleted.
import { describe, it, expect, vi } from "vitest";
import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

// The real archiveCase and its real walk, with a read that drops a new file into the case on every
// call — a background writer that never stops while the case is packaged.
vi.mock("../../src/analysis/caseArchive.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/analysis/caseArchive.js")>();
  let n = 0;
  return {
    ...actual,
    archiveCase: (...args: Parameters<typeof actual.archiveCase>) => {
      const [root, id, deps, name, dir] = args;
      const caseDir = dir ?? join(root, id);
      const churningRead = async (p: string): Promise<Buffer> => {
        await writeFile(join(caseDir, `churn-${++n}.txt`), "x");
        return readFile(p);
      };
      return actual.archiveCase(root, id, { ...deps, readFile: churningRead }, name, dir);
    },
  };
});

describe("ZIP delete of a case that never stops changing (#2801)", () => {
  it("answers 503 and deletes nothing", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-settle-final-")));
    const app = createApp(store, { stateStore: new StateStore(store) });
    await request(app)
      .post("/cases")
      .send({ caseId: "INC-S", name: "n", investigator: "i", aiProvider: null });
    expect((await request(app).patch("/cases/INC-S/status").send({ status: "closed" })).status).toBe(200);

    const res = await request(app).post("/cases/INC-S/delete").send({ archiveFirst: "zip" });
    expect(res.status).toBe(503);
    expect(res.body.code).toBe("DFIR_CASE_FILE_VANISHED");
    expect(res.body.error).toMatch(/appeared while the case was being packaged/);
    expect(await store.caseExists("INC-S")).toBe(true);
    expect((await readdir(store.casesRoot)).filter((f) => f.endsWith(".zip"))).toEqual([]);
  });
});
