import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { NotificationConfigStore } from "../../src/analysis/notificationStore.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { createNotifier } from "../../src/integrations/notify/notifyDispatch.js";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-notify-routes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const notificationStore = new NotificationConfigStore(join(root, "notifications", "config.json"));
  const slashCommandChannelStore = new SlashCommandChannelStore(
    join(root, "notifications", "slash-command-bindings.json"),
  );
  const sent: string[] = [];
  const fetchFn = (async (u: string) => {
    sent.push(String(u));
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
  // Mirrors the production wiring in runtimeStores.ts: the war-room bot's token, read per send.
  const notifier = createNotifier({
    store: notificationStore,
    fetchFn,
    telegramBotToken: () => process.env.DFIR_TELEGRAM_BOT_TOKEN,
  });
  const app = createApp(store, {
    stateStore,
    notificationStore,
    slashCommandChannelStore,
    notifier,
    notifyEmailEnabled: true,
    dashboardBaseUrl: "http://127.0.0.1:4773",
  });
  return { app, notificationStore, slashCommandChannelStore, sent };
}

// This file asserts on /notifications/status, which reads DFIR_TELEGRAM_BOT_TOKEN from the live
// environment — so it must not inherit whatever the shell that launched vitest happens to export.
// With the token set out there the route truthfully answers `true` and the default-state assertions
// fail for a reason that has nothing to do with the code. Cleared before EVERY test and restored
// after, which also gives the nested suite below a known floor to set its own value on top of.
const ambientTelegramToken = process.env.DFIR_TELEGRAM_BOT_TOKEN;
beforeEach(() => {
  delete process.env.DFIR_TELEGRAM_BOT_TOKEN;
});
afterEach(() => {
  if (ambientTelegramToken === undefined) delete process.env.DFIR_TELEGRAM_BOT_TOKEN;
  else process.env.DFIR_TELEGRAM_BOT_TOKEN = ambientTelegramToken;
});

describe("notification channel CRUD routes", () => {
  it("status reports configured + email transport", async () => {
    const { app } = await harness();
    const r = await request(app).get("/notifications/status");
    expect(r.body).toEqual({
      configured: true,
      emailEnabled: true,
      telegramEnvToken: false,
      telegramChats: [],
    });
  });

  it("creates, lists (redacted), updates (secret-preserving), and deletes a Slack channel", async () => {
    const { app } = await harness();
    expect((await request(app).get("/notifications")).body).toEqual([]);

    const add = await request(app).post("/notifications").send({
      type: "slack",
      name: "SOC",
      webhookUrl: "https://hooks.slack.com/services/secret",
      minSeverity: "High",
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
    const upd = await request(app)
      .put(`/notifications/${id}`)
      .send({ type: "slack", name: "SOC-2", webhookUrl: "", minSeverity: "Critical" });
    expect(upd.status).toBe(200);
    expect(upd.body.name).toBe("SOC-2");
    expect(upd.body.minSeverity).toBe("Critical");

    const del = await request(app).delete(`/notifications/${id}`);
    expect(del.status).toBe(204);
    expect((await request(app).get("/notifications")).body).toEqual([]);
  });

  it("rejects a bad channel (400) and a missing one (404)", async () => {
    const { app } = await harness();
    expect(
      (await request(app).post("/notifications").send({ type: "slack", webhookUrl: "nope" })).status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .post("/notifications")
          .send({ type: "email", smtp: { host: "", port: 0, from: "", to: "" } })
      ).status,
    ).toBe(400);
    expect(
      (await request(app).put("/notifications/ghost").send({ type: "slack", webhookUrl: "https://x/y" }))
        .status,
    ).toBe(404);
    expect((await request(app).delete("/notifications/ghost")).status).toBe(404);
  });

  // #684. The channel form is the OPSEC boundary: whatever the caller says here decides whether case
  // detail leaves the machine. z.coerce.boolean() applied JavaScript truthiness, so a client sending
  // the string "false" — an HTML form, a curl one-liner, any non-JSON caller — turned a channel and
  // its `critical_finding` toggle ON while asking for them OFF. These assert the wire contract, not
  // just the parser.
  describe("boolean toggles over the wire (#684)", () => {
    const base = { type: "slack", webhookUrl: "https://hooks.slack.com/services/x" };

    it("takes JSON booleans at face value", async () => {
      const { app, notificationStore } = await harness();
      const r = await request(app)
        .post("/notifications")
        .send({ ...base, enabled: false, events: { critical_finding: false } });
      expect(r.status).toBe(201);
      const [stored] = await notificationStore.load();
      expect(stored.enabled).toBe(false);
      expect(stored.events.critical_finding).toBe(false);
    });

    it('stores the string "false" as OFF, not as ON', async () => {
      const { app, notificationStore } = await harness();
      const r = await request(app)
        .post("/notifications")
        .send({ ...base, enabled: "false", events: { critical_finding: "false" } });
      expect(r.status).toBe(201);
      const [stored] = await notificationStore.load();
      expect(stored.enabled).toBe(false);
      expect(stored.events.critical_finding).toBe(false);
    });

    it('stores the string "true" as ON', async () => {
      const { app, notificationStore } = await harness();
      const r = await request(app)
        .post("/notifications")
        .send({ ...base, enabled: "true", events: { critical_finding: "true" } });
      expect(r.status).toBe(201);
      const [stored] = await notificationStore.load();
      expect(stored.enabled).toBe(true);
      expect(stored.events.critical_finding).toBe(true);
    });

    it("answers 400 for a number or a null instead of guessing", async () => {
      const { app, notificationStore } = await harness();
      for (const bad of [0, 1, null, "yes"]) {
        const r = await request(app)
          .post("/notifications")
          .send({ ...base, enabled: bad });
        expect(r.status, `enabled: ${JSON.stringify(bad)}`).toBe(400);
      }
      expect(await notificationStore.load()).toEqual([]);
    });

    it("applies the documented defaults when the toggles are omitted", async () => {
      const { app, notificationStore } = await harness();
      expect((await request(app).post("/notifications").send(base)).status).toBe(201);
      const [stored] = await notificationStore.load();
      expect(stored.enabled).toBe(true);
      expect(stored.events.critical_finding).toBe(true);
    });

    it('turns a saved channel OFF when an update sends "false"', async () => {
      const { app, notificationStore } = await harness();
      const add = await request(app).post("/notifications").send(base);
      const upd = await request(app)
        .put(`/notifications/${add.body.id}`)
        .send({ ...base, webhookUrl: "", enabled: "false" });
      expect(upd.status).toBe(200);
      const [stored] = await notificationStore.load();
      expect(stored.enabled).toBe(false);
      expect(stored.webhookUrl).toBe(base.webhookUrl); // same type, so the secret round-trips
    });
  });

  // #683. The webhook family shares a field, not an endpoint.
  it("refuses a provider-type change that leaves the webhook URL blank", async () => {
    const { app, notificationStore } = await harness();
    const add = await request(app)
      .post("/notifications")
      .send({ type: "slack", webhookUrl: "https://hooks.slack.com/services/secret" });
    const bad = await request(app)
      .put(`/notifications/${add.body.id}`)
      .send({ type: "discord", webhookUrl: "" });
    expect(bad.status).toBe(400);
    const [unchanged] = await notificationStore.load();
    expect(unchanged.type).toBe("slack");
    expect(unchanged.webhookUrl).toBe("https://hooks.slack.com/services/secret");

    const ok = await request(app)
      .put(`/notifications/${add.body.id}`)
      .send({ type: "discord", webhookUrl: "https://discord.com/api/webhooks/1/new" });
    expect(ok.status).toBe(200);
    const [switched] = await notificationStore.load();
    expect(switched.type).toBe("discord");
    expect(switched.webhookUrl).toBe("https://discord.com/api/webhooks/1/new");
  });

  it("test route sends to a channel via the notifier", async () => {
    const { app, sent } = await harness();
    const add = await request(app)
      .post("/notifications")
      .send({ type: "slack", webhookUrl: "https://hooks/test" });
    const t = await request(app).post("/notifications/test").send({ channelId: add.body.id });
    expect(t.status).toBe(200);
    expect(t.body.results).toHaveLength(1);
    expect(t.body.results[0].ok).toBe(true);
    expect(sent).toContain("https://hooks/test");
  });

  // #58 follow-up: an operator who already set DFIR_TELEGRAM_BOT_TOKEN for the war-room bot should
  // not have to paste the same token into the notification channel form.
  describe("telegram channels borrowing DFIR_TELEGRAM_BOT_TOKEN", () => {
    const ENV_TOKEN = "999:ENVTOKEN";
    // Runs after the file-level hook has cleared the ambient value, and the file-level afterEach
    // puts the operator's own back — so this only has to set what these tests need.
    beforeEach(() => {
      process.env.DFIR_TELEGRAM_BOT_TOKEN = ENV_TOKEN;
    });

    it("status reports the env token so the form can say it is already set", async () => {
      const { app } = await harness();
      expect((await request(app).get("/notifications/status")).body.telegramEnvToken).toBe(true);
    });

    it("status offers the chats the war-room bot is already bound to", async () => {
      const { app, slashCommandChannelStore } = await harness();
      await slashCommandChannelStore.bind("telegram:12345678", "demo");
      await slashCommandChannelStore.bind("slack:C1", "demo");
      const r = await request(app).get("/notifications/status");
      expect(r.body.telegramChats).toEqual([{ chatId: "12345678", caseId: "demo" }]);
    });

    it("offers no chats when the bindings store is not wired", async () => {
      const root = await mkdtemp(join(tmpdir(), "dfir-notify-nobind-"));
      const notificationStore = new NotificationConfigStore(join(root, "notifications", "config.json"));
      const app = createApp(new CaseStore(root), { notificationStore });
      expect((await request(app).get("/notifications/status")).body.telegramChats).toEqual([]);
    });

    it("accepts a channel with only a chat ID, and sends with the env token", async () => {
      const { app, sent } = await harness();
      const add = await request(app)
        .post("/notifications")
        .send({ type: "telegram", name: "SOC alerts", telegram: { chatId: "-100" } });
      expect(add.status).toBe(201);
      expect(add.body.telegram).toEqual({
        chatId: "-100",
        hasBotToken: true,
        usesEnvBotToken: true,
      });

      const list = await request(app).get("/notifications");
      expect(list.body[0].telegram.usesEnvBotToken).toBe(true);

      const t = await request(app).post("/notifications/test").send({ channelId: add.body.id });
      expect(t.body.results[0].ok).toBe(true);
      expect(sent).toContain(`https://api.telegram.org/bot${ENV_TOKEN}/sendMessage`);
    });

    it("keeps the env token out of the stored channel so rotating .env rotates the channel", async () => {
      const { app, notificationStore, sent } = await harness();
      const add = await request(app)
        .post("/notifications")
        .send({ type: "telegram", telegram: { chatId: "-100" } });
      const stored = await notificationStore.get(add.body.id);
      expect(stored?.telegram?.botToken).toBe("");

      process.env.DFIR_TELEGRAM_BOT_TOKEN = "111:ROTATED";
      await request(app).post("/notifications/test").send({ channelId: add.body.id });
      expect(sent).toContain("https://api.telegram.org/bot111:ROTATED/sendMessage");
    });

    it("still rejects a channel with no chat ID", async () => {
      const { app } = await harness();
      const r = await request(app)
        .post("/notifications")
        .send({ type: "telegram", telegram: { chatId: "  " } });
      expect(r.status).toBe(400);
      expect(r.body.error).toContain("chat ID");
    });
  });

  it("returns 501 when notifications are not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-notify-off-"));
    const store = new CaseStore(root);
    const app = createApp(store, {});
    expect((await request(app).get("/notifications")).body).toEqual([]);
    expect(
      (await request(app).post("/notifications").send({ type: "slack", webhookUrl: "https://x/y" })).status,
    ).toBe(501);
    expect((await request(app).get("/notifications/status")).body.configured).toBe(false);
  });
});
