import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportUndoStore } from "../../src/analysis/importUndo.js";
import { TemplateStore } from "../../src/analysis/templateStore.js";
import { ReportTemplateStore } from "../../src/reports/reportTemplateStore.js";
import { DashboardViewStore } from "../../src/analysis/dashboardViewStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";

const SECRET = JSON.stringify({ apiKey: "do-not-touch" });

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-trav-routes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  // The stores live one level below the sandbox, so `..` in an id reaches the sentinel beside them.
  const storesRoot = join(root, "stores");
  const secretPath = join(dirname(storesRoot), "secret.json");
  await writeFile(secretPath, SECRET, "utf8");
  const app = createApp(store, {
    pipeline,
    stateStore,
    importUndoStore: new ImportUndoStore(store),
    templateStore: new TemplateStore(join(storesRoot, "templates")),
    reportTemplateStore: new ReportTemplateStore(join(storesRoot, "report-templates")),
    dashboardViewStore: new DashboardViewStore(join(storesRoot, "views")),
    artifactBundleStore: new ArtifactBundleStore(join(storesRoot, "bundles")),
  });
  return { app, secretPath };
}

const intact = async (p: string): Promise<boolean> => (await readFile(p, "utf8")) === SECRET;

describe("store-id traversal over HTTP (#213)", () => {
  it("rejects a traversal id in a POST body with 400, not 500", async () => {
    const { app, secretPath } = await harness();
    for (const route of ["/templates", "/report-templates", "/bundles"]) {
      const res = await request(app).post(route).send({ id: "../../secret", name: "pwn" });
      expect(res.status, `${route} should reject the traversal id`).toBe(400);
      expect(await intact(secretPath), `${route} must not have written the sentinel`).toBe(true);
    }
  });

  it("rejects an encoded traversal id in the path with 400", async () => {
    const { app, secretPath } = await harness();
    // %2e%2e%2f decodes to ../ before the route sees it — the store must still refuse.
    for (const route of ["/templates", "/report-templates", "/bundles"]) {
      const res = await request(app).delete(`${route}/%2e%2e%2f%2e%2e%2fsecret`);
      expect([400, 404]).toContain(res.status);
      expect(await intact(secretPath), `${route} must not have deleted the sentinel`).toBe(true);
    }
  });

  it("still creates and lists a legitimate custom template", async () => {
    const { app } = await harness();
    const created = await request(app).post("/templates").send({ id: "my-playbook", name: "Mine" });
    expect(created.status).toBe(201);
    const fetched = await request(app).get("/templates/my-playbook");
    expect(fetched.status).toBe(200);
    expect(fetched.body.name).toBe("Mine");
  });
});
