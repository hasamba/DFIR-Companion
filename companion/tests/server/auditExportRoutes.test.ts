import { describe, it, expect, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AuditExportStore } from "../../src/analysis/auditExportStore.js";
import { AuditCursorStore } from "../../src/analysis/auditExportCursor.js";
import { createAuditExporter } from "../../src/integrations/audit/auditExporter.js";

// #929 end to end over HTTP: add a destination, never leak its credential, forward what an analyst
// does, and back-fill on demand.

type FetchArgs = [url: string, init?: { method?: string; body?: string; headers?: Record<string, string> }];

async function makeApp(fetchImpl?: (...args: FetchArgs) => Promise<Response>) {
  const root = await mkdtemp(join(tmpdir(), "dfir-audit-routes-"));
  const store = new CaseStore(root);
  const activityLogStore = new ActivityLogStore(store);
  const auditExportStore = new AuditExportStore(join(root, "audit-export", "config.json"));
  const auditExportCursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
  const fetchFn = vi.fn<(...args: FetchArgs) => Promise<Response>>(
    fetchImpl ?? (async () => new Response(JSON.stringify({ text: "Success", code: 0 }), { status: 200 })),
  );
  const auditExporter = createAuditExporter({
    store: auditExportStore,
    cursors: auditExportCursors,
    activity: activityLogStore,
    listCaseIds: async () => (await store.listCases()).map((c) => c.caseId),
    transport: { fetchFn: fetchFn as never, syslogSend: async () => {}, hostname: "h" },
  });
  const app = createApp(store, {
    activityLogStore,
    auditExportStore,
    auditExportCursors,
    auditExporter,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, fetchFn, auditExportCursors, activityLogStore, exporter: auditExporter };
}

const splunk = {
  type: "splunk",
  name: "SOC",
  splunk: { url: "https://splunk:8088", token: "hec-secret" },
};

describe("GET/POST /audit-export", () => {
  it("starts with no destinations — nothing leaves the box by default", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/audit-export");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, destinations: [] });
  });

  it("adds a destination and never returns its credential", async () => {
    const { app } = await makeApp();
    const created = await request(app).post("/audit-export").send(splunk);
    expect(created.status).toBe(201);
    expect(JSON.stringify(created.body)).not.toContain("hec-secret");
    expect(created.body.splunk).toMatchObject({ url: "https://splunk:8088", hasToken: true });

    const list = await request(app).get("/audit-export");
    expect(JSON.stringify(list.body)).not.toContain("hec-secret");
    expect(list.body.destinations).toHaveLength(1);
  });

  it("refuses a destination that could not reach anything", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/audit-export")
      .send({ type: "splunk", splunk: { url: "not-a-url", token: "t" } });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/http/i);
  });

  it("keeps the saved token when an edit leaves the redacted field blank", async () => {
    const { app, fetchFn } = await makeApp();
    const created = await request(app).post("/audit-export").send(splunk);
    const updated = await request(app)
      .put(`/audit-export/${created.body.id}`)
      .send({ type: "splunk", name: "SOC Splunk", splunk: { url: "https://splunk:8088", token: "" } });
    expect(updated.status).toBe(200);
    expect(updated.body.name).toBe("SOC Splunk");
    expect(updated.body.splunk.hasToken).toBe(true);
    // Prove the token survived by watching what the send actually presents.
    await request(app).post("/audit-export/test").send({ destinationId: created.body.id });
    const headers = fetchFn.mock.calls[0]?.[1]?.headers ?? {};
    expect(headers.Authorization).toBe("Splunk hec-secret");
  });

  it("404s an unknown destination on update and delete", async () => {
    const { app } = await makeApp();
    expect((await request(app).put("/audit-export/nope").send(splunk)).status).toBe(404);
    expect((await request(app).delete("/audit-export/nope")).status).toBe(404);
  });

  it("deleting a destination forgets its delivery positions", async () => {
    const { app, auditExportCursors } = await makeApp();
    const created = await request(app).post("/audit-export").send(splunk);
    await auditExportCursors.set(created.body.id, "c1", 7);
    expect((await request(app).delete(`/audit-export/${created.body.id}`)).status).toBe(204);
    expect(await auditExportCursors.get(created.body.id, "c1")).toBe(0);
  });
});

describe("enabling a destination does not ship the history", () => {
  it("a destination created enabled starts at the end of each case's log", async () => {
    // What the Settings pane promises, and what the first version broke: an unseeded position is
    // zero, so the next analyst action dragged the whole case history to the collector.
    const { app, fetchFn, activityLogStore, auditExportCursors, exporter } = await makeApp();
    await activityLogStore.add("c1", { category: "triage", action: "a", detail: "old one" });
    await activityLogStore.add("c1", { category: "triage", action: "b", detail: "old two" });

    const created = await request(app)
      .post("/audit-export")
      .send({ ...splunk, enabled: true });
    expect(created.status).toBe(201);
    expect(created.body.enabled).toBe(true);
    expect(await auditExportCursors.get(created.body.id, "c1")).toBe(2);

    // Nothing was sent while adding it.
    expect(fetchFn).not.toHaveBeenCalled();

    // And the next action — only that one — goes.
    await activityLogStore.add("c1", { category: "triage", action: "c", detail: "new one" });
    await exporter.exportCase("c1");
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const body = String(fetchFn.mock.calls[0]?.[1]?.body);
    expect(body).toContain("new one");
    expect(body).not.toContain("old one");
  });

  it("a destination added disabled then switched on starts at the end too", async () => {
    const { app, fetchFn, activityLogStore, auditExportCursors, exporter } = await makeApp();
    const created = await request(app)
      .post("/audit-export")
      .send({ ...splunk, enabled: false });
    expect(created.body.enabled).toBe(false);
    // History accumulates while it is off. Turning it on must not be a retroactive decision.
    await activityLogStore.add("c1", { category: "triage", action: "a", detail: "while off" });
    await activityLogStore.add("c1", { category: "triage", action: "b", detail: "also off" });

    const on = await request(app)
      .put(`/audit-export/${created.body.id}`)
      .send({
        type: "splunk",
        name: "SOC",
        enabled: true,
        splunk: { url: "https://splunk:8088", token: "" },
      });
    expect(on.status).toBe(200);
    expect(on.body.enabled).toBe(true);
    expect(await auditExportCursors.get(created.body.id, "c1")).toBe(2);

    await activityLogStore.add("c1", { category: "triage", action: "c", detail: "after on" });
    await exporter.exportCase("c1");
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(String(fetchFn.mock.calls[0]?.[1]?.body)).toContain("after on");
  });

  it("switching a destination off and on again does not re-send what it missed", async () => {
    const { app, activityLogStore, auditExportCursors, exporter } = await makeApp();
    const created = await request(app)
      .post("/audit-export")
      .send({ ...splunk, enabled: true });
    await activityLogStore.add("c1", { category: "triage", action: "a", detail: "one" });
    await exporter.exportCase("c1");
    const body = { type: "splunk", name: "SOC", splunk: { url: "https://splunk:8088", token: "" } };
    await request(app)
      .put(`/audit-export/${created.body.id}`)
      .send({ ...body, enabled: false });
    await activityLogStore.add("c1", { category: "triage", action: "b", detail: "gap" });
    await request(app)
      .put(`/audit-export/${created.body.id}`)
      .send({ ...body, enabled: true });
    // Re-seeded to the end: the gap is not forwarded, which is what "only what happens next" means.
    expect(await auditExportCursors.get(created.body.id, "c1")).toBe(2);
  });

  it("an edit that changes nothing about enablement leaves the position alone", async () => {
    const { app, activityLogStore, auditExportCursors, exporter } = await makeApp();
    const created = await request(app)
      .post("/audit-export")
      .send({ ...splunk, enabled: true });
    await activityLogStore.add("c1", { category: "triage", action: "a", detail: "one" });
    await exporter.exportCase("c1");
    expect(await auditExportCursors.get(created.body.id, "c1")).toBe(1);
    await activityLogStore.add("c1", { category: "triage", action: "b", detail: "two" });
    // A rename while already enabled must NOT re-seed — that would skip the pending entry.
    await request(app)
      .put(`/audit-export/${created.body.id}`)
      .send({
        type: "splunk",
        name: "Renamed",
        enabled: true,
        splunk: { url: "https://splunk:8088", token: "" },
      });
    expect(await auditExportCursors.get(created.body.id, "c1")).toBe(1);
  });

  it("refuses an edit that repoints the collector with a blank token", async () => {
    const { app } = await makeApp();
    const created = await request(app).post("/audit-export").send(splunk);
    const moved = await request(app)
      .put(`/audit-export/${created.body.id}`)
      .send({ type: "splunk", splunk: { url: "https://elsewhere:8088", token: "" } });
    expect(moved.status).toBe(400);
    expect(moved.body.error).toMatch(/collector URL/i);
  });
});

describe("POST /audit-export/test", () => {
  it("sends one marked record and reports the result", async () => {
    const { app, fetchFn } = await makeApp();
    const created = await request(app).post("/audit-export").send(splunk);
    const res = await request(app).post("/audit-export/test").send({ destinationId: created.body.id });
    expect(res.status).toBe(200);
    expect(res.body.results[0]).toMatchObject({ ok: true, sent: 1 });
    expect(fetchFn.mock.calls[0]?.[1]).toMatchObject({ method: "POST" });
    expect(String(fetchFn.mock.calls[0]?.[1]?.body)).toContain("audit_export_test");
  });

  it("404s when no destination matches", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/audit-export/test").send({ destinationId: "nope" });
    expect(res.status).toBe(404);
  });

  it("reports the collector's rejection rather than a 500", async () => {
    const { app } = await makeApp(async () => new Response("bad token", { status: 403 }));
    const created = await request(app).post("/audit-export").send(splunk);
    const res = await request(app).post("/audit-export/test").send({ destinationId: created.body.id });
    expect(res.status).toBe(200);
    expect(res.body.results[0].ok).toBe(false);
    expect(res.body.results[0].error).toContain("403");
  });
});

describe("forwarding an analyst action", () => {
  it("what the activity log stores is what the destination receives", async () => {
    // This is the seam appWiring's onActivity hook drives: an append, then exportCase for that
    // case. A bare createApp does not install that hook, so the exporter is driven directly here —
    // what is under test is that a REAL stored entry reaches the wire intact.
    const { app, fetchFn, activityLogStore, exporter } = await makeApp();
    await request(app).post("/audit-export").send(splunk);
    await activityLogStore.add("c1", {
      actor: "alice",
      category: "triage",
      action: "mark_false_positive",
      detail: "finding f3",
    });
    const results = await exporter.exportCase("c1");
    expect(results[0]).toMatchObject({ ok: true, sent: 1, caseId: "c1" });
    const body = String(fetchFn.mock.calls[0]?.[1]?.body);
    const sent = JSON.parse(body).event;
    expect(sent).toMatchObject({
      caseId: "c1",
      category: "triage",
      action: "mark_false_positive",
      detail: "finding f3",
      actor: "alice",
      outcome: "success",
      // No authenticated session in this app, so the name is the client's claim and the record
      // says so. That distinction is the feed's whole compliance value.
      actorVerified: false,
    });
    expect(sent.id).toBeTruthy();

    // A second run forwards nothing — the position is durable.
    fetchFn.mockClear();
    expect((await exporter.exportCase("c1"))[0].sent).toBe(0);
    expect(fetchFn).not.toHaveBeenCalled();

    const status = await request(app).get("/audit-export");
    expect(status.body.destinations[0].status.sentTotal).toBe(1);
  });

  it("backfill forwards the case history and reports what went", async () => {
    const { app, fetchFn, activityLogStore } = await makeApp();
    const created = await request(app).post("/audit-export").send(splunk);
    await activityLogStore.add("c1", { category: "triage", action: "a", detail: "one" });
    await activityLogStore.add("c1", { category: "triage", action: "b", detail: "two" });
    const res = await request(app).post(`/audit-export/${created.body.id}/backfill`).send({});
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ sent: 2, cases: 1, failed: [] });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const body = String(fetchFn.mock.calls[0]?.[1]?.body);
    expect(body).toContain('"detail":"one"');
    expect(body).toContain('"detail":"two"');
    // A second backfill is a deliberate re-send, and the records carry the same ids so a SIEM can
    // collapse them.
    const again = await request(app).post(`/audit-export/${created.body.id}/backfill`).send({});
    expect(again.body.sent).toBe(2);
  });

  it("backfill 404s an unknown destination", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/audit-export/nope/backfill").send({});
    expect(res.status).toBe(404);
  });

  it("a failed backfill reports the failure per case instead of throwing", async () => {
    const { app, activityLogStore } = await makeApp(async () => new Response("down", { status: 503 }));
    const created = await request(app).post("/audit-export").send(splunk);
    await activityLogStore.add("c1", { category: "triage", action: "a", detail: "one" });
    const res = await request(app).post(`/audit-export/${created.body.id}/backfill`).send({});
    expect(res.status).toBe(200);
    expect(res.body.sent).toBe(0);
    expect(res.body.failed[0]).toMatchObject({ caseId: "c1" });
    expect(res.body.failed[0].error).toContain("503");
  });
});

describe("when the feature is not wired at all", () => {
  it("reports itself unconfigured rather than 404-ing", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-audit-off-"));
    const app = createApp(new CaseStore(root), {});
    const res = await request(app).get("/audit-export");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, destinations: [] });
    expect((await request(app).post("/audit-export").send(splunk)).status).toBe(501);
    expect((await request(app).post("/audit-export/test").send({})).status).toBe(501);
  });
});
