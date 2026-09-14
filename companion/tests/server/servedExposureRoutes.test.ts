import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ServedLocationStore } from "../../src/analysis/servedLocation.js";
import { createApp } from "../../src/server.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { mapCombinedLogLine } from "../../src/analysis/combinedLogImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { loadFilteredState } from "../../src/reports/filteredState.js";
import { normalizeReportTemplate, REPORT_SECTION_DEFS } from "../../src/reports/reportTemplate.js";

// #930 item 4 routes: declare → read the exposure → report; validation and bounds refused by name.

const line = `203.0.113.9 - - [01/Jun/2026:02:00:00 +0000] "GET /backup/db.sql HTTP/1.1" 200 48213 "-" "curl/8"`;

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-served-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const servedLocationStore = new ServedLocationStore(store);
  const state = emptyState("c1");
  const web = mapCombinedLogLine(line, new Map<string, SiemIoc>())!;
  state.forensicTimeline = [
    {
      id: "f1",
      timestamp: "2026-06-01T01:00:00.000Z",
      description: "Sysmon File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WEB01",
      path: "C:\\inetpub\\wwwroot\\backup\\db.sql",
      sources: ["Sysmon"],
      canonical: {
        event: { category: "file", type: "create" },
        file: { path: "C:\\inetpub\\wwwroot\\backup\\db.sql" },
      } as never,
    },
    {
      ...web,
      id: "w1",
      asset: "WEB01",
      mitreTechniques: web.mitre,
      relatedFindingIds: [],
      sourceScreenshots: [],
    },
  ];
  await stateStore.save(state);
  const app = createApp(store, { stateStore, servedLocationStore });
  return { app, store, stateStore };
}

describe("served exposure routes", () => {
  it("declare → exposure → report; a bad prefix or root is refused by name; delete", async () => {
    const { app, store, stateStore } = await harness();
    expect(
      (
        await request(app)
          .post("/cases/c1/served-locations")
          .send({ host: "WEB01", urlPrefix: "backup", localRoot: "C:\\x" })
      ).status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .post("/cases/c1/served-locations")
          .send({ host: "WEB01", urlPrefix: "/", localRoot: "relative" })
      ).body.error,
    ).toContain("absolute");
    expect(
      (
        await request(app)
          .post("/cases/nope/served-locations")
          .send({ host: "h", urlPrefix: "/", localRoot: "/x" })
      ).status,
    ).toBe(404);
    const declared = await request(app)
      .post("/cases/c1/served-locations")
      .send({
        host: "WEB01",
        urlPrefix: "/",
        localRoot: "C:\\inetpub\\wwwroot",
        sensitive: ["backup/db.sql"],
      });
    expect(declared.status).toBe(201);
    const lid = declared.body.location.id as string;
    const exposure = await request(app).get("/cases/c1/served-exposure");
    expect(exposure.body, JSON.stringify(exposure.body).slice(0, 400)).not.toHaveProperty("error");
    expect(exposure.status).toBe(200);
    const r = exposure.body.locations[0].resources[0];
    expect(r).toMatchObject({
      url: "/backup/db.sql",
      stage: "corroborated-disclosure",
      sensitivity: "confirmed-by-analyst",
    });
    expect(r.requests[0]).toMatchObject({
      eventId: "w1",
      status: 200,
      size: 48213,
      sizeRecorded: true,
      placement: "covered",
    });
    expect(JSON.stringify(exposure.body)).not.toMatch(/"transfer/);
    // Report: off unless opted in; renders the stage, the reason and the size words.
    const filtered = await loadFilteredState({ state: stateStore, cases: store }, "c1");
    expect(filtered.servedLocations).toHaveLength(1);
    const only = normalizeReportTemplate({
      sections: REPORT_SECTION_DEFS.map((d) => ({ key: d.key, enabled: d.key === "servedExposure" })),
    });
    const md = renderMarkdownReport(filtered, undefined, undefined, undefined, undefined, undefined, only);
    expect(md).toContain("## Served exposure");
    expect(md).toContain("corroborated-disclosure");
    expect(md).toContain("a logged response size is what the server said");
    expect(
      renderMarkdownReport(
        filtered,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        // An existing saved template (one that lists sections) does not sprout it.
        normalizeReportTemplate({ sections: [{ key: "timeline", enabled: true }] }),
      ),
    ).not.toContain("## Served exposure");
    expect((await request(app).delete(`/cases/c1/served-locations/${lid}`)).status).toBe(204);
    expect((await request(app).delete(`/cases/c1/served-locations/${lid}`)).status).toBe(404);
    expect((await request(app).get("/cases/c1/served-exposure")).body.locations).toEqual([]);
  });
});
