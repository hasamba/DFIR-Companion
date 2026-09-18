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
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// Harness mirrors tests/server/veloBundle.test.ts: a real CaseStore + StateStore + a runtime pipeline
// built via buildRuntimePipeline with NO AI provider (the declarative import path is deterministic and
// makes no AI call), plus an ImporterStore so the /importers routes + custom-importer dispatch are live.
async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-improutes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const importerStore = new ImporterStore(join(root, "importers"));
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
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
    const r = await request(app)
      .post("/importers")
      .send({ spec: { id: "Bad" } });
    expect(r.status).toBe(400);
    expect(r.body.errors.length).toBeGreaterThan(0);
  });

  it(
    "adds an importer, lists it, imports a matching file through it, then deletes it",
    async () => {
      const { app } = await harness();

      const add = await request(app).post("/importers").send({ spec: EXAMPLE_IMPORTER_SPEC });
      expect(add.status).toBe(201);
      expect(add.body.id).toBe("mde-advanced-hunting");

      const list = await request(app).get("/importers");
      expect(list.body.importers.map((m: { id: string }) => m.id)).toContain("mde-advanced-hunting");
      expect(list.body.precedence).toBe("builtin-first");

      const imp = await request(app)
        .post("/cases/c1/import")
        .send({ text: MDE_CSV, filename: "advanced-hunting.csv" });
      expect(imp.status).toBe(202);
      expect(imp.body.kind).toBe("mde-advanced-hunting");

      // Poll the case state until the deterministic import lands its forensic events (no AI involved).
      const evs = await pollFor(
        "the custom importer to land a forensic event in the case state",
        async () => {
          const st = await request(app).get("/cases/c1/state");
          const n = (st.body.forensicTimeline ?? []).length;
          return n > 0 ? n : undefined;
        },
      );
      expect(evs).toBeGreaterThan(0);

      const del = await request(app).delete("/importers/mde-advanced-hunting");
      expect(del.status).toBe(200);
      expect((await request(app).get("/importers")).body.importers).toHaveLength(0);
    },
    POLL_TIMEOUT_MS * 2,
  ); // one poll budget, doubled to leave room for setup + assertions

  it("toggles precedence", async () => {
    const { app } = await harness();
    const r = await request(app).put("/importers/precedence").send({ precedence: "external-first" });
    expect(r.status).toBe(200);
    expect((await request(app).get("/importers")).body.precedence).toBe("external-first");
  });

  // Per-importer health (#84): a successful custom-importer run should show up in /diagnostics'
  // per-importer breakdown with last-run age, rows parsed, and no error.
  it(
    "records a successful custom-importer run in /diagnostics' per-importer breakdown",
    async () => {
      const { app } = await harness();
      await request(app).post("/importers").send({ spec: EXAMPLE_IMPORTER_SPEC });
      await request(app).post("/cases/c1/import").send({ text: MDE_CSV, filename: "advanced-hunting.csv" });

      let seen: string[] = [];
      const row = await pollFor<{
        lastStatus?: string;
        kept?: number;
        lastRunAt?: string;
        lastError?: string | null;
      }>(
        () => `/diagnostics to report a run for mde-advanced-hunting, saw importers [${seen.join(", ")}]`,
        async () => {
          const diag = await request(app).get("/diagnostics");
          const perImporter = diag.body.report.importers.perImporter as { id: string; lastStatus?: string }[];
          seen = perImporter.map((p) => p.id);
          const found = perImporter.find((p) => p.id === "mde-advanced-hunting");
          return found?.lastStatus == null ? undefined : found;
        },
      );
      expect(row.lastStatus).toBe("ok");
      expect(row.kept).toBeGreaterThan(0);
      expect(row.lastRunAt).toBeTruthy();
      expect(row.lastError).toBeNull();
    },
    POLL_TIMEOUT_MS * 2,
  );
});

// #1124: /cases/:id/import's own "could not detect the file type" 400 names a capa-specific
// reason when the body is recognizably capa-shaped (real identity fields) but not a static report
// — an end-to-end HTTP proof this route actually wires capaFlavorHintFor in, not just a unit test
// on the pure function.
describe("capa dynamic-flavor diagnostic (#1124)", () => {
  it("names the flavor instead of the generic unknown-format message", async () => {
    const { app } = await harness();
    const dynamicCapaReport = JSON.stringify({
      meta: {
        flavor: "dynamic",
        sample: {
          md5: "7a450304b58917290f54ffbdccb095b6",
          sha1: "db054d79d4d913671732d9ff696dca69f911601a",
          sha256: "afed46612dce2c6fa48d95192426366dcc0a4517f4b56240f0c8e39a5104748a",
          path: "samples/sample.dll",
        },
      },
      rules: {},
    });
    const r = await request(app)
      .post("/cases/c1/import")
      .send({ text: dynamicCapaReport, filename: "capa-dynamic.json" });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe(
      'capa report flavor "dynamic" is not yet supported (only "static" reports are parsed)',
    );
  });

  it("still fires on realistically indented JSON (capa pretty-prints; the fixture above is compact)", async () => {
    const { app } = await harness();
    const dynamicCapaReport = JSON.stringify(
      {
        meta: {
          flavor: "dynamic",
          sample: {
            md5: "7a450304b58917290f54ffbdccb095b6",
            sha1: "db054d79d4d913671732d9ff696dca69f911601a",
            sha256: "afed46612dce2c6fa48d95192426366dcc0a4517f4b56240f0c8e39a5104748a",
            path: "samples/sample.dll",
          },
        },
        rules: {},
      },
      null,
      2,
    );
    const r = await request(app)
      .post("/cases/c1/import")
      .send({ text: dynamicCapaReport, filename: "capa-dynamic.json" });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe(
      'capa report flavor "dynamic" is not yet supported (only "static" reports are parsed)',
    );
  });

  it("never fires the capa hint for an unrelated JSON object (falls to the SIEM catch-all as usual)", async () => {
    const { app } = await harness();
    const r = await request(app)
      .post("/cases/c1/import")
      .send({ text: JSON.stringify({ hello: "world" }), filename: "mystery.json" });
    // Established, deliberate behavior: any object-shaped JSON that matches no specific importer
    // falls to the SIEM importer's own lenient field auto-detection (detectJson's final `return
    // "siem"`), not a 400 — this test only proves the new capa check doesn't misfire on it.
    expect(r.status).toBe(202);
    expect(r.body.kind).toBe("siem");
  });
});
