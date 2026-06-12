import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import { createNotifier } from "../../src/integrations/notify/notifyDispatch.js";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-notify-routes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const notificationStore = new NotificationConfigStore(join(root, "notifications", "config.json"));
  const sent: string[] = [];
  const fetchFn = (async (u: string) => { sent.push(String(u)); return new Response("ok", { status: 200 }); }) as typeof fetch;
  const notifier = createNotifier({ store: notificationStore, fetchFn });
  const app = createApp(store, { stateStore, notificationStore, notifier, notifyEmailEnabled: true, dashboardBaseUrl: "http://127.0.0.1:4773" });
  return { app, notificationStore, sent };
}

describe("notification channel CRUD routes", () => {
  it("status reports configured + email transport", async () => {
    const { app } = await harness();
    const r = await request(app).get("/notifications/status");
    expect(r.body).toEqual({ configured: true, emailEnabled: true });
  });

  it("creates, lists (redacted), updates (secret-preserving), and deletes a Slack channel", async () => {
    const { app } = await harness();
    expect((await request(app).get("/notifications")).body).toEqual([]);

    const add = await request(app).post("/notifications").send({
      type: "slack", name: "SOC", webhookUrl: "https://hooks.slack.com/services/secret", minSeverity: "High",
    });
    expect(add.status).toBe(201);
    // Secret redacted in the response.
    expect(add.body.webhookUrl).toBeUndefined();
    expect(add.body.hasWebhookUrl).toBe(true);
    const id = add.body.id;

    const list = await request(app).get("/notifications");
    expect(list.body).toHaveLength(1);
    expect(list.body[0].webhookUrl).toBeUndefined();

    // Update with a BLANK webhook (the redacted round-trip) keeps the saved secret.
    const upd = await request(app).put(`/notifications/${id}`).send({ type: "slack", name: "SOC-2", webhookUrl: "", minSeverity: "Critical" });
    expect(upd.status).toBe(200);
    expect(upd.body.name).toBe("SOC-2");
    expect(upd.body.minSeverity).toBe("Critical");

    const del = await request(app).delete(`/notifications/${id}`);
    expect(del.status).toBe(204);
    expect((await request(app).get("/notifications")).body).toEqual([]);
  });

  it("rejects a bad channel (400) and a missing one (404)", async () => {
    const { app } = await harness();
    expect((await request(app).post("/notifications").send({ type: "slack", webhookUrl: "nope" })).status).toBe(400);
    expect((await request(app).post("/notifications").send({ type: "email", smtp: { host: "", port: 0, from: "", to: "" } })).status).toBe(400);
    expect((await request(app).put("/notifications/ghost").send({ type: "slack", webhookUrl: "https://x/y" })).status).toBe(404);
    expect((await request(app).delete("/notifications/ghost")).status).toBe(404);
  });

  it("test route sends to a channel via the notifier", async () => {
    const { app, sent } = await harness();
    const add = await request(app).post("/notifications").send({ type: "slack", webhookUrl: "https://hooks/test" });
    const t = await request(app).post("/notifications/test").send({ channelId: add.body.id });
    expect(t.status).toBe(200);
    expect(t.body.results).toHaveLength(1);
    expect(t.body.results[0].ok).toBe(true);
    expect(sent).toContain("https://hooks/test");
  });

  it("returns 501 when notifications are not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-notify-off-"));
    const store = new CaseStore(root);
    const app = createApp(store, {});
    expect((await request(app).get("/notifications")).body).toEqual([]);
    expect((await request(app).post("/notifications").send({ type: "slack", webhookUrl: "https://x/y" })).status).toBe(501);
    expect((await request(app).get("/notifications/status")).body.configured).toBe(false);
  });
});
