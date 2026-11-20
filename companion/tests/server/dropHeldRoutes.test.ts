import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { huntHeldStoreFor } from "../../src/analysis/huntHeldStore.js";

// #2755: list the files in drop/_held/, and Import anyway / Skip them. Synthetic values only.

const REL = "_held/hunt/WS-A-C.1/results/Hayabusa.json";

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-held-routes-")));
  const app = createApp(store, {});
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const drop = join(store.caseDir("c1"), "drop");
  await mkdir(join(drop, "_held", "hunt", "WS-A-C.1", "results"), { recursive: true });
  await writeFile(join(drop, ...REL.split("/")), '{"a":1}\n');
  await huntHeldStoreFor(store).putHeld("c1", {
    ...{ rel: REL, origin: "zip", source: "hunt.zip", artifact: "Hayabusa", host: "WS-A" },
    ...{ bytes: 8, groupBytes: 8, reason: "host", limitMb: 50 },
  });
  return { app, drop };
}

describe("held hunt file routes (#2755)", () => {
  it("lists the files in _held/ with what is known about them", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/drop/held");
    expect(res.status).toBe(200);
    expect(res.body.limits).toEqual({ hostMb: 50, totalMb: 200 });
    expect(res.body.files).toEqual([
      expect.objectContaining({ rel: REL, artifact: "Hayabusa", reason: "host" }),
    ]);
  });

  it("Import anyway moves the file back into drop/; Skip moves it to _skipped/", async () => {
    const { app, drop } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/drop/held/decide")
      .send({
        decisions: [
          { rel: REL, decision: "import" },
          { rel: "_held/nope.json", decision: "skip" },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body.moved).toEqual([{ rel: REL, to: "hunt/WS-A-C.1/results/Hayabusa.json" }]);
    expect(res.body.ignored).toHaveLength(1);
    expect(existsSync(join(drop, "hunt", "WS-A-C.1", "results", "Hayabusa.json"))).toBe(true);
    expect((await request(app).get("/cases/c1/drop/held")).body.files).toEqual([]);
  });

  it("refuses a path outside _held/, a malformed body, and an unknown case", async () => {
    const { app } = await makeApp();
    const out = await request(app)
      .post("/cases/c1/drop/held/decide")
      .send({ decisions: [{ rel: "../../etc/passwd", decision: "import" }] });
    expect(out.body).toMatchObject({ updated: 0, ignored: [{ why: "not a held file" }] });
    for (const body of [{}, { decisions: [] }, { decisions: [{ rel: REL, decision: "delete" }] }])
      expect((await request(app).post("/cases/c1/drop/held/decide").send(body)).status).toBe(400);
    expect((await request(app).get("/cases/nope/drop/held")).status).toBe(404);
  });

  it.skipIf(process.platform === "win32")(
    "refuses to move a file whose folder links outside drop/",
    async () => {
      const { app, drop } = await makeApp();
      const outside = await mkdtemp(join(tmpdir(), "dfir-outside-"));
      await writeFile(join(outside, "secret.json"), "{}\n");
      await symlink(outside, join(drop, "_held", "link"));
      const res = await request(app)
        .post("/cases/c1/drop/held/decide")
        .send({ decisions: [{ rel: "_held/link/secret.json", decision: "import" }] });
      expect(res.body.updated).toBe(0);
      expect(res.body.ignored[0].why).toMatch(/outside drop/);
      expect(existsSync(join(outside, "secret.json"))).toBe(true);
    },
  );
});
