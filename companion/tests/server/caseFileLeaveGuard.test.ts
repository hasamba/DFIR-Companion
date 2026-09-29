import { describe, it, expect, beforeEach } from "vitest";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";
import { makeImageLoader } from "../../src/analysis/imageLoader.js";
import { buildRedactedExport, type RedactedExportDeps } from "../../src/reports/redactedExportBuilder.js";
import { CaseFileRefusedError } from "../../src/storage/caseFileRead.js";

// #1846 sweep: every other place a case file leaves the host by name — the report download, the
// screenshot sent to an AI provider, the redacted package — reads through storage/caseFileRead.ts.
// Each test plants a link to another case's file and checks that its bytes never leave.
const POSIX = process.platform !== "win32";
const SECRET = "other-case-secret-token";

let store: CaseStore;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-leave-")));
  for (const id of ["c1", "c2"]) {
    await store.createCase({ caseId: id, name: id, investigator: "alice", aiProvider: null });
    await mkdir(store.screenshotsDir(id), { recursive: true });
    await mkdir(store.reportsDir(id), { recursive: true });
  }
  await writeFile(join(store.screenshotsDir("c2"), "000001_x.png"), SECRET);
  await writeFile(join(store.reportsDir("c2"), "report.md"), SECRET);
});

describe.skipIf(!POSIX)("case files that leave the host refuse a planted link (#1846)", () => {
  it("GET /cases/:id/report/:file refuses report.md linked to another case", async () => {
    await symlink(join(store.reportsDir("c2"), "report.md"), join(store.reportsDir("c1"), "report.md"));
    const app = createApp(store, { stateStore: new StateStore(store) });
    const res = await request(app).get("/cases/c1/report/report.md");
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/symlink detected at "report\.md"/);
    expect(res.text).not.toContain(SECRET);
  });

  it("GET /cases/:id/report/:file still serves a plain report", async () => {
    await writeFile(join(store.reportsDir("c1"), "report.md"), "# own report");
    const app = createApp(store, { stateStore: new StateStore(store) });
    const res = await request(app).get("/cases/c1/report/report.md");
    expect(res.status).toBe(200);
    expect(res.text).toContain("# own report");
  });

  it("the AI image loader refuses a screenshot linked to another case", async () => {
    await symlink(
      join(store.screenshotsDir("c2"), "000001_x.png"),
      join(store.screenshotsDir("c1"), "000001_x.png"),
    );
    await expect(makeImageLoader(store)("c1", "000001_x.png")).rejects.toBeInstanceOf(CaseFileRefusedError);
  });

  it("the redacted package refuses a screenshot linked to another case", async () => {
    await symlink(
      join(store.screenshotsDir("c2"), "000001_x.png"),
      join(store.screenshotsDir("c1"), "000001_x.png"),
    );
    const deps: RedactedExportDeps = {
      store,
      stateStore: {
        load: async () => ({ forensicTimeline: [], findings: [], iocs: [] }),
      } as unknown as RedactedExportDeps["stateStore"],
      customEntities: { load: async () => [] } as unknown as RedactedExportDeps["customEntities"],
      discoveredEntities: {
        load: async () => ({ discovered: [], suppressed: [] }),
      } as unknown as RedactedExportDeps["discoveredEntities"],
      ocrRunner: { recognize: async () => [] },
      reportWriter: {
        redactedReportContents: async () => ({
          markdown: "m",
          html: "h",
          findingsCsv: "f",
          iocsCsv: "i",
          timelineCsv: "t",
          forensicTimelineCsv: "ft",
          stateJson: "{}",
        }),
      },
      redactImage: async (buf: Buffer) => ({
        buffer: buf,
        blurred: false,
        redactionCount: 0,
        metadataStripped: true,
      }),
    };
    await expect(
      buildRedactedExport(deps, "c1", { includeScreenshots: true, blurScreenshots: false } as never),
    ).rejects.toBeInstanceOf(CaseFileRefusedError);
  });
});
