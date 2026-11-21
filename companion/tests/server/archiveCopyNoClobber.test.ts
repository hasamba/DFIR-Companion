// #2787: the server-side copy an encrypted delete (or a ZIP archive) saves in the cases root exists
// for the case where the analyst never got the download. A later delete or archive of a case with
// the same id and name must never replace it — it gets a " (2)" name instead.
import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";

const PASSWORD = "correct horse battery staple";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-noclobber-"));
  const store = new CaseStore(root);
  const app = createApp(store, {
    stateStore: new StateStore(store),
    commentsStore: new CommentsStore(store),
  });
  return { app, store };
}

async function seedClosedCase(app: ReturnType<typeof createApp>, caseId: string, name: string) {
  await request(app).post("/cases").send({ caseId, name, investigator: "alice", aiProvider: "anthropic" });
  expect((await request(app).patch(`/cases/${caseId}/status`).send({ status: "closed" })).status).toBe(200);
}

function bufferRequest(req: request.Test): request.Test {
  return req.buffer().parse((r, cb) => {
    const chunks: Buffer[] = [];
    r.on("data", (c: Buffer) => chunks.push(c));
    r.on("end", () => cb(null, Buffer.concat(chunks)));
  });
}

async function encryptedDelete(app: ReturnType<typeof createApp>, caseId: string) {
  const res = await bufferRequest(
    request(app).post(`/cases/${caseId}/delete`).send({ archiveFirst: "encrypted", password: PASSWORD }),
  );
  expect(res.status).toBe(200);
  expect(res.headers["x-case-deleted"]).toBe("true");
  return { path: decodeURIComponent(String(res.headers["x-archive-path"])), body: res.body as Buffer };
}

describe("server-side archive copies are never overwritten (#2787)", () => {
  it("a second encrypted delete of the same id and name keeps the first copy", async () => {
    const { app, store } = await harness();
    await seedClosedCase(app, "dup1", "Dup Case");
    const first = await encryptedDelete(app, "dup1");
    expect(first.path).toBe(join(store.casesRoot, "dup1 - Dup Case.dfircase"));

    await seedClosedCase(app, "dup1", "Dup Case");
    const second = await encryptedDelete(app, "dup1");
    expect(second.path).toBe(join(store.casesRoot, "dup1 - Dup Case (2).dfircase"));

    expect((await readFile(first.path)).equals(first.body)).toBe(true);
    expect((await readFile(second.path)).equals(second.body)).toBe(true);
    expect((await readdir(store.casesRoot)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  it("a second ZIP delete of the same id and name keeps the first ZIP", async () => {
    const { app, store } = await harness();
    await seedClosedCase(app, "dup2", "Dup Case");
    const first = await request(app).post("/cases/dup2/delete").send({ archiveFirst: "zip" });
    expect(first.status).toBe(200);
    const firstBytes = await readFile(first.body.archivePath);

    await seedClosedCase(app, "dup2", "Dup Case");
    const second = await request(app).post("/cases/dup2/delete").send({ archiveFirst: "zip" });
    expect(second.status).toBe(200);

    expect(first.body.archivePath).toBe(join(store.casesRoot, "dup2 - Dup Case (no password).zip"));
    expect(second.body.archivePath).toBe(join(store.casesRoot, "dup2 - Dup Case (no password) (2).zip"));
    expect((await readFile(first.body.archivePath)).equals(firstBytes)).toBe(true);
  });
});
