import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile, symlink, link } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { createApp } from "../../src/server.js";

/**
 * #818: GET /cases/:id/evidence/:file validated the filename (a safe path component) and then read
 * the path with a plain readFile, which follows symlinks. Whoever can write into the case's
 * screenshots/ or imports/ directory — shared storage, a synced folder, an imported artifact that
 * drops a link — could replace an evidence file with a symlink to any host-readable file and have
 * the dashboard serve its contents as evidence. The export path already read through
 * storage/noFollowRead.ts; the evidence route did not.
 *
 * These tests plant the link BEFORE the request (the route never had a check for a link that is
 * already in place, so this is the whole bug, not just its race). The swap-during-read race itself
 * is exercised by tests/storage/noFollowRead.test.ts against the shared primitive.
 */
const SECRET = "root:$6$not-for-the-dashboard:19000:0:99999:7:::\n";

let store: CaseStore;
let app: ReturnType<typeof createApp>;
let outside: string;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-evlink-"));
  store = new CaseStore(root);
  app = createApp(store, { stateStore: new StateStore(store), commentsStore: new CommentsStore(store) });
  await store.createCase({ caseId: "c1", name: "Case", investigator: "alice", aiProvider: null });
  await mkdir(store.screenshotsDir("c1"), { recursive: true });
  await mkdir(store.importsDir("c1"), { recursive: true });
  // The "host file" lives outside every case directory, as /etc/shadow would.
  outside = await mkdtemp(join(tmpdir(), "dfir-evlink-host-"));
  await writeFile(join(outside, "shadow"), SECRET);
});

describe("GET /cases/:id/evidence/:file — link guard (#818)", () => {
  it("refuses a symlink planted in screenshots/ and never serves its target", async () => {
    await symlink(join(outside, "shadow"), join(store.screenshotsDir("c1"), "000001_x.png"));

    const res = await request(app).get("/cases/c1/evidence/000001_x.png");

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/symlink detected/);
    expect(res.text).not.toContain("not-for-the-dashboard");
    // The client's filename, never the on-disk path the guard saw.
    expect(res.body.error).not.toContain(outside);
  });

  it("refuses a symlink planted in imports/ too", async () => {
    await symlink(join(outside, "shadow"), join(store.importsDir("c1"), "0001_results.csv"));

    const res = await request(app).get("/cases/c1/evidence/0001_results.csv");

    expect(res.status).toBe(403);
    expect(res.text).not.toContain("not-for-the-dashboard");
  });

  it("refuses a hardlink, which no symlink check can see", async () => {
    // Same filesystem is required for link(); the temp dirs above share one.
    await link(join(outside, "shadow"), join(store.importsDir("c1"), "0001_results.csv"));

    const res = await request(app).get("/cases/c1/evidence/0001_results.csv");

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/hardlink detected/);
    expect(res.text).not.toContain("not-for-the-dashboard");
  });

  it("a dangling symlink is refused as a link, not reported as missing", async () => {
    await symlink(join(outside, "gone"), join(store.screenshotsDir("c1"), "000002_x.png"));

    const res = await request(app).get("/cases/c1/evidence/000002_x.png");

    expect(res.status).toBe(403);
  });

  it("still serves a plain evidence file beside the refused link (no over-blocking)", async () => {
    await symlink(join(outside, "shadow"), join(store.importsDir("c1"), "0001_results.csv"));
    await writeFile(join(store.importsDir("c1"), "0002_results.csv"), "host,verdict\nws1,clean\n");

    const res = await request(app).get("/cases/c1/evidence/0002_results.csv");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^text\/plain/); // csv is served as text so a click opens it in a tab
    expect(res.text).toContain("ws1,clean");
    expect((await request(app).get("/cases/c1/evidence/missing.csv")).status).toBe(404);
  });
});
