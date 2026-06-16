import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImporterStore } from "../../src/analysis/importerStore.js";
import { EXAMPLE_IMPORTER_SPEC } from "../../src/analysis/importerSpec.js";

// Harness mirrors tests/server/veloBundle.test.ts: a real CaseStore + StateStore + a runtime pipeline
// built via buildRuntimePipeline with NO AI provider (the declarative import path is deterministic and
// makes no AI call), plus an ImporterStore so the /importers routes + custom-importer dispatch are live.
async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-improutes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importerStore = new ImporterStore(join(root, "importers"));
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importerStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app };
}

const MDE_CSV =
  "Timestamp,DeviceName,ActionType,FileName,Severity,SHA256,RemoteIP\n" +
  "2026-06-10T12:00:00Z,HOST01,ProcessCreated,evil.exe,High,abc123,9.9.9.9";

describe("custom importer routes", () => {
  it("rejects an invalid spec with field-pathed errors", async () => {
    const { app } = await harness();
    const r = await request(app).post("/importers").send({ spec: { id: "Bad" } });
    expect(r.status).toBe(400);
    expect(r.body.errors.length).toBeGreaterThan(0);
  });

  it("adds an importer, lists it, imports a matching file through it, then deletes it", async () => {
    const { app } = await harness();

    const add = await request(app).post("/importers").send({ spec: EXAMPLE_IMPORTER_SPEC });
    expect(add.status).toBe(201);
    expect(add.body.id).toBe("mde-advanced-hunting");

    const list = await request(app).get("/importers");
    expect(list.body.importers.map((m: { id: string }) => m.id)).toContain("mde-advanced-hunting");
    expect(list.body.precedence).toBe("builtin-first");

    const imp = await request(app).post("/cases/c1/import").send({ text: MDE_CSV, filename: "advanced-hunting.csv" });
    expect(imp.status).toBe(202);
    expect(imp.body.kind).toBe("mde-advanced-hunting");

    // Poll the case state until the deterministic import lands its forensic events (no AI involved).
    let evs = 0;
    for (let i = 0; i < 40 && evs === 0; i++) {
      const st = await request(app).get("/cases/c1/state");
      evs = (st.body.forensicTimeline ?? []).length;
      if (evs === 0) await new Promise((r) => setTimeout(r, 25));
    }
    expect(evs).toBeGreaterThan(0);

    const del = await request(app).delete("/importers/mde-advanced-hunting");
    expect(del.status).toBe(200);
    expect((await request(app).get("/importers")).body.importers).toHaveLength(0);
  });

  it("toggles precedence", async () => {
    const { app } = await harness();
    const r = await request(app).put("/importers/precedence").send({ precedence: "external-first" });
    expect(r.status).toBe(200);
    expect((await request(app).get("/importers")).body.precedence).toBe("external-first");
  });
});
