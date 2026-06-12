import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import type { OcrRunner } from "../../src/analysis/ocrRedact.js";

// OCR runner that always "reads" an internal IP at a fixed box — so the blur path is exercised
// deterministically without tesseract.
const stubOcr: OcrRunner = {
  recognize: async () => [{ text: "10.0.0.5", bbox: { x: 4, y: 4, w: 60, h: 14 }, confidence: 96 }],
};

let app: ReturnType<typeof createApp>;
let cases: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-redactexport-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

  const stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState("c1"),
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: "VICTIM-PC connected to 10.0.0.5 with password=Sup3rSecret",
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "VICTIM-PC",
      },
    ],
  });

  // A real PNG on disk so the export's screenshot lister finds it.
  const png = await sharp({ create: { width: 120, height: 40, channels: 3, background: { r: 255, g: 255, b: 255 } } })
    .png()
    .toBuffer();
  await cases.saveScreenshot("c1", "shot-001.png", png);

  app = createApp(cases, {
    stateStore,
    reportWriter: new ReportWriter(cases, stateStore),
    ocrRunner: stubOcr,
  });
});

describe("GET /cases/:id/export/redacted", () => {
  it("returns a ZIP attachment with an anonymized report, redacted screenshot, and notes", async () => {
    const res = await request(app).get("/cases/c1/export/redacted").buffer().parse((r, cb) => {
      const chunks: Buffer[] = [];
      r.on("data", (c: Buffer) => chunks.push(c));
      r.on("end", () => cb(null, Buffer.concat(chunks)));
    });

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("application/zip");
    expect(res.headers["content-disposition"]).toContain("case-c1-redacted.zip");

    const entries = readZip(res.body as Buffer);
    const byPath = new Map(entries.map((e) => [e.path, e.data]));

    expect(byPath.has("REDACTION-NOTES.txt")).toBe(true);
    const md = byPath.get("report/report.md")!.toString("utf8");
    // internal host + IP tokenized; secret one-way redacted; real values gone
    expect(md).toContain("ANON_HOST_1");
    expect(md).toContain("ANON_IP_1");
    expect(md).toContain("[REDACTED_SECRET]");
    expect(md).not.toContain("VICTIM-PC");
    expect(md).not.toContain("10.0.0.5");
    expect(md).not.toContain("Sup3rSecret");
    // the screenshot was included and re-encoded (PII boxed) — differs from the on-disk original
    expect(byPath.has("screenshots/shot-001.png")).toBe(true);
  });

  it("omits screenshots when ?screenshots=0", async () => {
    const res = await request(app).get("/cases/c1/export/redacted?screenshots=0").buffer().parse((r, cb) => {
      const chunks: Buffer[] = [];
      r.on("data", (c: Buffer) => chunks.push(c));
      r.on("end", () => cb(null, Buffer.concat(chunks)));
    });
    expect(res.status).toBe(200);
    const paths = readZip(res.body as Buffer).map((e) => e.path);
    expect(paths.some((p) => p.startsWith("screenshots/"))).toBe(false);
    expect(paths).toContain("report/report.md");
  });

  it("501s when the report writer is not configured", async () => {
    const bare = createApp(cases, {});
    const res = await request(bare).get("/cases/c1/export/redacted");
    expect(res.status).toBe(501);
  });
});
