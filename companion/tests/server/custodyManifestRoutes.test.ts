import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { loadOrCreateInstanceSecret } from "../../src/analysis/instanceSecret.js";
import {
  verifyCustodyManifest,
  CUSTODY_MANIFEST_FILENAME,
  type CustodyManifest,
} from "../../src/analysis/custodyManifest.js";
import { importEncryptedCase } from "../../src/analysis/caseExportArchive.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-custodymanifestroute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  app = createApp(cases, {
    custodyStore: new CustodyStore(cases),
    stateStore,
    reportWriter: new ReportWriter(cases, stateStore),
  });
  await cases.saveImport("c1", "0001_evidence.csv", "ts,message\n2026-01-01T00:00:00Z,hi\n");
});

describe("GET /cases/:id/custody/manifest", () => {
  it("returns a manifest that verifies under this instance's secret", async () => {
    const res = await request(app).get("/cases/c1/custody/manifest");

    expect(res.status).toBe(200);
    const manifest = res.body as CustodyManifest;
    expect(manifest.caseId).toBe("c1");
    expect(manifest.artifacts).toHaveLength(1);
    expect(verifyCustodyManifest(manifest, loadOrCreateInstanceSecret(root))).toBe(true);
  });

  it("404s for a case that does not exist", async () => {
    expect((await request(app).get("/cases/nope/custody/manifest")).status).toBe(404);
  });

  it("501s when no custody store is configured", async () => {
    expect((await request(createApp(cases, {})).get("/cases/c1/custody/manifest")).status).toBe(501);
  });
});

describe("custody manifest in the report", () => {
  it("is written alongside the report when one is generated", async () => {
    const res = await request(app).post("/cases/c1/report").send({});
    expect(res.status).toBe(200);

    const raw = await readFile(join(cases.reportsDir("c1"), CUSTODY_MANIFEST_FILENAME), "utf8");
    expect(verifyCustodyManifest(JSON.parse(raw) as CustodyManifest, loadOrCreateInstanceSecret(root))).toBe(
      true,
    );
  });
});

function bufferRequest(req: request.Test): request.Test {
  return req.buffer().parse((r, cb) => {
    const chunks: Buffer[] = [];
    r.on("data", (c: Buffer) => chunks.push(c));
    r.on("end", () => cb(null, Buffer.concat(chunks)));
  });
}

describe("custody manifest in the encrypted archive", () => {
  it("ships inside the .dfircase so the recipient can verify the chain", async () => {
    const res = await bufferRequest(
      request(app).post("/cases/c1/export/encrypted").send({ password: "a-long-enough-password" }),
    );
    expect(res.status).toBe(200);

    const target = await mkdtemp(join(tmpdir(), "dfir-manifest-import-"));
    const into = new CaseStore(target);
    await importEncryptedCase(into, res.body as Buffer, "a-long-enough-password", { targetCaseId: "c1" });

    const raw = await readFile(join(into.caseDir("c1"), CUSTODY_MANIFEST_FILENAME), "utf8");
    const manifest = JSON.parse(raw) as CustodyManifest;
    expect(manifest.artifacts).toHaveLength(1);
    // Signed by the EXPORTING instance, so it still verifies under that secret after travelling.
    expect(verifyCustodyManifest(manifest, loadOrCreateInstanceSecret(root))).toBe(true);
  });
});
