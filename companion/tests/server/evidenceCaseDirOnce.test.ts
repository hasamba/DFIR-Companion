import { describe, it, expect, vi } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { mkdirSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";

/**
 * #2145: GET /cases/:id/evidence/:file worked out the case folder twice — once for the candidate
 * paths, once for the read scope. An archive move landing between the two put the candidate under
 * <root>/<id> and the scope under <root>/_archived/<id>, so the read refused the file as a "protected
 * file" and the route answered a 403 security refusal for what was only a case that moved. The route
 * now resolves the folder once: a move after that point is a plain 404.
 */
describe("evidence route resolves the case folder once (#2145)", () => {
  it("a case archived mid-request answers 404, never a false 403 security refusal", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ev-once-"));
    const store = new CaseStore(root);
    const app = createApp(store, { stateStore: new StateStore(store) });
    await store.createCase({ caseId: "c1", name: "Case", investigator: "alice", aiProvider: null });
    await mkdir(store.screenshotsDir("c1"), { recursive: true });
    await writeFile(join(store.screenshotsDir("c1"), "shot.png"), "not really a png");

    const real = store.caseDir.bind(store);
    let moved = false;
    const spy = vi.spyOn(store, "caseDir").mockImplementation((id: string) => {
      const dir = real(id);
      // Earlier middleware also looks the folder up; only the evidence route's own look counts.
      const fromRoute = new Error().stack?.includes("captures") ?? false;
      if (fromRoute && !moved) {
        // The archive move lands right after the route's first look at the folder.
        moved = true;
        mkdirSync(join(root, "_archived"), { recursive: true });
        renameSync(join(root, "c1"), join(root, "_archived", "c1"));
      }
      return dir;
    });

    const res = await request(app).get("/cases/c1/evidence/shot.png");
    spy.mockRestore();
    expect(moved).toBe(true);
    expect(res.status).not.toBe(403);
    expect(res.status).toBe(404);
  });

  it("still serves the file when nothing moves", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ev-once-"));
    const store = new CaseStore(root);
    const app = createApp(store, { stateStore: new StateStore(store) });
    await store.createCase({ caseId: "c1", name: "Case", investigator: "alice", aiProvider: null });
    await mkdir(store.importsDir("c1"), { recursive: true });
    await writeFile(join(store.importsDir("c1"), "rows.csv"), "a,b\n1,2\n");
    const res = await request(app).get("/cases/c1/evidence/rows.csv");
    expect(res.status).toBe(200);
    expect(res.text).toBe("a,b\n1,2\n");
  });
});
