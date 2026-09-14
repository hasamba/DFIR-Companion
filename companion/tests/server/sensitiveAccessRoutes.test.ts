import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SensitiveLocationStore } from "../../src/analysis/sensitiveLocation.js";
import { createApp } from "../../src/server.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { loadFilteredState } from "../../src/reports/filteredState.js";
import { normalizeReportTemplate, REPORT_SECTION_DEFS } from "../../src/reports/reportTemplate.js";

// #930 item 7: declare → the reading over real Windows records through the importer → report.

const elastic = (...sources: object[]) =>
  JSON.stringify({ data: sources.map((s) => ({ _index: "win", _type: "winevtx", _source: s })) });
const sec = (event_id: number, ts: string, event_data: Record<string, string>, log_name = "Security") => ({
  "@timestamp": ts,
  log_name,
  computer_name: "FS01.corp.local",
  event_id,
  level: "Information",
  event_data,
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-sens-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const sensitiveLocationStore = new SensitiveLocationStore(store);
  const state = emptyState("c1");
  const parsed = parseSiemExport(
    elastic(
      sec(4624, "2026-06-01T09:00:00Z", {
        TargetDomainName: "CORP",
        TargetUserName: "jdoe",
        TargetLogonId: "0x3e7",
        LogonType: "10",
        IpAddress: "203.0.113.9",
      }),
      sec(
        1,
        "2026-06-01T09:05:00Z",
        {
          UtcTime: "2026-06-01 09:05:00.000",
          ProcessId: "420",
          ProcessGuid: "{11111111-2222-3333-4444-555555555555}",
          Image: "C:\\Windows\\System32\\notepad.exe",
          CommandLine: "notepad.exe",
          User: "CORP\\jdoe",
        },
        "Microsoft-Windows-Sysmon/Operational",
      ),
      sec(
        11,
        "2026-06-01T08:00:00Z",
        {
          UtcTime: "2026-06-01 08:00:00.000",
          Image: "C:\\Windows\\explorer.exe",
          TargetFilename: "C:\\Finance\\Board\\minutes.docx",
          ProcessGuid: "{a}",
        },
        "Microsoft-Windows-Sysmon/Operational",
      ),
      sec(4663, "2026-06-01T09:10:00Z", {
        SubjectUserName: "jdoe",
        SubjectDomainName: "CORP",
        SubjectUserSid: "S-1-5-21-1-2-3-1001",
        SubjectLogonId: "0x3e7",
        ObjectType: "File",
        ObjectName: "C:\\Finance\\Board\\minutes.docx",
        HandleId: "0x1234",
        AccessMask: "0x1",
        ProcessId: "0x1a4",
        ProcessName: "C:\\Windows\\System32\\notepad.exe",
      }),
    ),
  );
  state.forensicTimeline = parsed.events.map((e, i) => ({
    ...e,
    id: `e${i}`,
    relatedFindingIds: [],
    sourceScreenshots: [],
  }));
  await stateStore.save(state);
  const app = createApp(store, { stateStore, sensitiveLocationStore });
  return { app, store, stateStore };
}

describe("sensitive access routes", () => {
  it("declare → reading → report; a relative path or a bad kind is refused by name; delete", async () => {
    const { app, store, stateStore } = await harness();
    expect(
      (await request(app).post("/cases/c1/sensitive-locations").send({ path: "Finance\\x", kind: "file" }))
        .body.error,
    ).toContain("absolute");
    expect(
      (await request(app).post("/cases/c1/sensitive-locations").send({ path: "C:\\x", kind: "thing" }))
        .status,
    ).toBe(400);
    expect(
      (await request(app).post("/cases/nope/sensitive-locations").send({ path: "C:\\x", kind: "file" }))
        .status,
    ).toBe(404);
    const declared = await request(app)
      .post("/cases/c1/sensitive-locations")
      .send({ host: "FS01.corp.local", path: "C:\\Finance\\Board", kind: "folder", note: "board papers" });
    expect(declared.status).toBe(201);
    const lid = declared.body.location.id as string;
    const reading = await request(app).get("/cases/c1/sensitive-access");
    expect(reading.status).toBe(200);
    const o = reading.body.locations[0].objects[0];
    expect(o).toMatchObject({
      path: "C:\\Finance\\Board\\minutes.docx",
      stage: "read-by-candidate-instance",
    });
    expect(o.accesses[0]).toMatchObject({
      classes: ["read-or-listing"],
      dataRead: true,
      pid: 420,
      instance: { state: "candidate", processGuid: "11111111-2222-3333-4444-555555555555" },
      session: { state: "candidate", logonType: 10, sourceAddress: "203.0.113.9" },
    });
    expect(JSON.stringify(reading.body)).not.toMatch(/exfil|staged|transferred/i);
    const filtered = await loadFilteredState({ state: stateStore, cases: store }, "c1");
    expect(filtered.sensitiveLocations).toHaveLength(1);
    const only = normalizeReportTemplate({
      sections: REPORT_SECTION_DEFS.map((d) => ({ key: d.key, enabled: d.key === "sensitiveAccess" })),
    });
    const md = renderMarkdownReport(filtered, undefined, undefined, undefined, undefined, undefined, only);
    expect(md).toContain("## Sensitive access");
    expect(md).toContain("read-by-candidate-instance");
    expect(
      renderMarkdownReport(
        filtered,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        normalizeReportTemplate({ sections: [{ key: "timeline", enabled: true }] }),
      ),
    ).not.toContain("## Sensitive access");
    expect((await request(app).delete(`/cases/c1/sensitive-locations/${lid}`)).status).toBe(204);
    expect((await request(app).delete(`/cases/c1/sensitive-locations/${lid}`)).status).toBe(404);
    expect((await request(app).get("/cases/c1/sensitive-access")).body.locations).toEqual([]);
  });
});
