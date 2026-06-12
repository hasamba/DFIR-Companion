import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { LegitimateStore } from "../../src/analysis/legitimate.js";
import { ReportMetaStore } from "../../src/reports/reportMeta.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { ReportTemplateStore } from "../../src/reports/reportTemplateStore.js";
import { ReportTemplateControlStore } from "../../src/reports/reportTemplateControl.js";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-rt-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const reportMetaStore = new ReportMetaStore(store);
  const reportTemplateStore = new ReportTemplateStore(join(root, "report-templates"));
  const reportTemplateControlStore = new ReportTemplateControlStore(store);
  const reportWriter = new ReportWriter(
    store, stateStore, new ScopeStore(store), new LegitimateStore(store), reportMetaStore,
    undefined, undefined, undefined, undefined, reportTemplateStore, reportTemplateControlStore,
  );
  const app = createApp(store, { stateStore, reportWriter, reportMetaStore, reportTemplateStore, reportTemplateControlStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store };
}

const reportMd = (store: CaseStore) => readFile(join(store.reportsDir("c1"), "report.md"), "utf8");

describe("report template CRUD routes", () => {
  it("lists the built-in templates", async () => {
    const { app } = await harness();
    const list = await request(app).get("/report-templates");
    expect(list.status).toBe(200);
    const ids = list.body.map((t: { id: string }) => t.id);
    expect(ids).toContain("standard");
    expect(ids).toContain("executive-brief");
    expect(list.body.every((t: { builtIn: boolean }) => t.builtIn)).toBe(true);
  });

  it("creates, fetches, and deletes a custom template", async () => {
    const { app } = await harness();
    const created = await request(app).post("/report-templates").send({ name: "Client Brief", accentColor: "#ff8800" });
    expect(created.status).toBe(201);
    expect(created.body.id).toBeTruthy();
    expect(created.body.accentColor).toBe("#ff8800");

    const got = await request(app).get(`/report-templates/${created.body.id}`);
    expect(got.status).toBe(200);
    expect(got.body.name).toBe("Client Brief");

    const del = await request(app).delete(`/report-templates/${created.body.id}`);
    expect(del.status).toBe(204);
    expect((await request(app).get(`/report-templates/${created.body.id}`)).status).toBe(404);
  });

  it("rejects a nameless template (400) and an unknown delete (404)", async () => {
    const { app } = await harness();
    expect((await request(app).post("/report-templates").send({ accentColor: "#000000" })).status).toBe(400);
    expect((await request(app).delete("/report-templates/ghost")).status).toBe(404);
  });

  it("edits a built-in in place and resets it on delete", async () => {
    const { app } = await harness();
    const saved = await request(app).post("/report-templates").send({ id: "standard", name: "Standard", accentColor: "#101010" });
    expect(saved.body.customized).toBe(true);
    expect((await request(app).get("/report-templates/standard")).body.accentColor).toBe("#101010");
    // delete resets the built-in (still 204, not 404)
    expect((await request(app).delete("/report-templates/standard")).status).toBe(204);
    expect((await request(app).get("/report-templates/standard")).body.accentColor).toBe("#2d6cdf");
  });
});

describe("per-case template selection drives report rendering", () => {
  it("defaults to 'standard' and renders every section", async () => {
    const { app, store } = await harness();
    expect((await request(app).get("/cases/c1/report-template")).body.templateId).toBe("standard");
    expect((await request(app).post("/cases/c1/report")).status).toBe(200);
    const md = await reportMd(store);
    expect(md).toContain("## 3 Timeline of events");
    expect(md).toContain("## 4 Investigation");
    expect(md).toContain("# Incident Investigation Report");
  });

  it("an executive-brief selection drops the technical sections", async () => {
    const { app, store } = await harness();
    const put = await request(app).put("/cases/c1/report-template").send({ templateId: "executive-brief" });
    expect(put.status).toBe(200);
    expect(put.body.templateId).toBe("executive-brief");

    await request(app).post("/cases/c1/report");
    const md = await reportMd(store);
    expect(md).toContain("## 2 Executive summary");
    expect(md).toContain("## 5 Conclusions and recommendations");
    expect(md).not.toContain("## 3 Timeline of events");
    expect(md).not.toContain("## 4 Investigation");
  });

  it("a custom template's branded header/footer/cover interpolate report metadata", async () => {
    const { app, store } = await harness();
    await request(app).put("/cases/c1/report-meta").send({ organization: "ExampleCorp", incidentId: "INC-9", restrictions: "TLP:RED" });
    const tpl = await request(app).post("/report-templates").send({
      name: "Branded",
      coverTitle: "Investigation for {{organization}}",
      headerText: "{{organization}}{{#if incidentId}} · {{incidentId}}{{/if}}",
      footerText: "{{restrictions}}",
      accentColor: "#aa0000",
    });
    await request(app).put("/cases/c1/report-template").send({ templateId: tpl.body.id });

    await request(app).post("/cases/c1/report");
    const md = await reportMd(store);
    expect(md).toContain("# Investigation for ExampleCorp");
    expect(md).toContain("> ExampleCorp · INC-9");   // running header banner
    expect(md).toContain("_TLP:RED_");                // footer banner

    // The accent colour flows into the HTML export's stylesheet.
    const html = await readFile(join(store.reportsDir("c1"), "report.html"), "utf8");
    expect(html).toContain("#aa0000");
  });

  it("falls back to the default template when the selected one was deleted", async () => {
    const { app, store } = await harness();
    const tpl = await request(app).post("/report-templates").send({ name: "Temp", sections: [{ key: "titlePage", enabled: true }, { key: "timeline", enabled: false }] });
    await request(app).put("/cases/c1/report-template").send({ templateId: tpl.body.id });
    await request(app).delete(`/report-templates/${tpl.body.id}`);

    await request(app).post("/cases/c1/report");
    const md = await reportMd(store);
    expect(md).toContain("## 3 Timeline of events"); // default restored, timeline present again
  });
});
