import { describe, it, expect, afterAll } from "vitest";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { createRuntimeStores } from "../../src/composition/runtimeStores.js";
import { buildAppOptions } from "../../src/composition/appWiring.js";
import { createApp } from "../../src/server.js";

// #1913, end to end: the investigator typed in the New case form shows up in Case Details (which reads
// GET /report-meta) and on the Markdown report's title page, without the analyst re-typing it.

const roots: string[] = [];

async function harness() {
  const base = await mkdtemp(join(tmpdir(), "dfir-case-investigator-"));
  roots.push(base);
  const root = join(base, "cases");
  await mkdir(root);
  const rt = createRuntimeStores({ casesRoot: root, host: "127.0.0.1", port: 0, logDir: join(base, "logs") });
  const app = createApp(rt.store, buildAppOptions(rt, {} as Parameters<typeof buildAppOptions>[1]));
  return { app, store: rt.store };
}

afterAll(async () => {
  for (const root of roots) await rm(root, { recursive: true, force: true });
});

describe("creation-time investigator reaches Case Details and the report (#1913)", () => {
  it("is in GET /report-meta and on the Markdown report", async () => {
    const { app, store } = await harness();
    const created = await request(app)
      .post("/cases")
      .send({ caseId: "inv-1", name: "n", investigator: "alice" });
    expect(created.status).toBe(201);

    const meta = await request(app).get("/cases/inv-1/report-meta");
    expect(meta.status).toBe(200);
    expect(meta.body.investigators).toEqual(["alice"]);

    const report = await request(app).post("/cases/inv-1/report").send({});
    expect(report.status).toBe(200);
    const md = await readFile(join(store.reportsDir("inv-1"), "report.md"), "utf8");
    expect(md).toContain("**Investigator:** alice");
    expect(md).not.toContain("investigator not set");
  });

  it("an analyst's saved list wins over the creation-time investigator", async () => {
    const { app } = await harness();
    await request(app).post("/cases").send({ caseId: "inv-2", name: "n", investigator: "alice" });
    const put = await request(app)
      .put("/cases/inv-2/report-meta")
      .send({ investigators: ["bob", "carol"] });
    expect(put.status).toBe(200);
    expect((await request(app).get("/cases/inv-2/report-meta")).body.investigators).toEqual(["bob", "carol"]);
  });
});
