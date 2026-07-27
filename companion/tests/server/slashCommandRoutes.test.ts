import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { createApp } from "../../src/server.js";

// End-to-end coverage for the war-room slash-command bot's HTTP surface (#235): authentication,
// rate limiting, the case guards, and the per-platform response envelopes. The pure parser and
// formatters are covered in tests/analysis/slashCommand.test.ts.

const SLACK_SECRET = "slack-signing-secret";
const TEAMS_TOKEN = "teams-token";
const TELEGRAM_SECRET = "telegram-secret";

let store: CaseStore;
let stateStore: StateStore;
let activityLogStore: ActivityLogStore;
let bindings: SlashCommandChannelStore;
let app: ReturnType<typeof createApp>;
let asked: Array<{ caseId: string; question: string }>;
let delivered: Array<{ url: string; body: unknown }>;

const fakePipeline = {
  ask: async (caseId: string, question: string) => {
    asked.push({ caseId, question });
    return { answer: `answer for ${caseId}`, status: "answered", pointer: "collect the prefetch dir", relatedEventIds: [] };
  },
} as unknown as import("../../src/analysis/pipeline.js").AnalysisPipeline;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-slashroute-"));
  const bindDir = await mkdtemp(join(tmpdir(), "dfir-slashbind-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await store.createCase({ caseId: "c2", name: "n2", investigator: "i", aiProvider: null });
  stateStore = new StateStore(store);
  activityLogStore = new ActivityLogStore(store);
  bindings = new SlashCommandChannelStore(join(bindDir, "slash-command-bindings.json"));
  asked = [];
  delivered = [];

  // Stub fetch for EVERY test, not just the delivery ones. An async command's result is posted to
  // the request's response_url, so an unstubbed test that runs `ask` makes a real request to
  // hooks.slack.com — network traffic from a unit test, flaky offline, and attributed to whichever
  // test happens to be running when the warning lands. Individual tests override this to assert on
  // the payload; this default just makes sure nothing escapes.
  vi.stubGlobal("fetch", async (url: string, init: { body: string }) => {
    delivered.push({ url, body: JSON.parse(init.body) });
    return new Response("ok", { status: 200 });
  });

  vi.stubEnv("DFIR_SLACK_SIGNING_SECRET", SLACK_SECRET);
  vi.stubEnv("DFIR_TEAMS_TOKEN", TEAMS_TOKEN);
  vi.stubEnv("DFIR_TELEGRAM_SECRET_TOKEN", TELEGRAM_SECRET);
  vi.stubEnv("DFIR_SLACK_ACTION_USERS", "");
  vi.stubEnv("DFIR_TELEGRAM_ACTION_USERS", "");

  // Reset BEFORE createApp: the route captures the limiter singleton at registration time.
  resetLimiters();
  app = createApp(store, {
    stateStore,
    activityLogStore,
    slashCommandChannelStore: bindings,
    pipeline: fakePipeline,
  });
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

// ── request helpers ─────────────────────────────────────────────────────────────────────

function slack(text: string, extra: Record<string, string> = {}) {
  const raw = new URLSearchParams({
    channel_id: "C1", user_id: "U1", text, response_url: "https://hooks.slack.com/commands/T1/1/x", ...extra,
  }).toString();
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = "v0=" + createHmac("sha256", SLACK_SECRET).update(`v0:${ts}:${raw}`).digest("hex");
  return request(app)
    .post("/integrations/slack/command")
    .set("content-type", "application/x-www-form-urlencoded")
    .set("x-slack-request-timestamp", ts)
    .set("x-slack-signature", sig)
    .send(raw);
}

function teams(text: string, extra: Record<string, unknown> = {}) {
  return request(app)
    .post("/integrations/teams/command")
    .set("authorization", `Bearer ${TEAMS_TOKEN}`)
    .send({ channel: { id: "T-CH" }, from: { id: "U1" }, text, responseUrl: "https://outlook.webhook.office.com/x", ...extra });
}

function telegram(text: string, extra: Record<string, unknown> = {}) {
  return request(app)
    .post("/integrations/telegram/command")
    .set("x-telegram-bot-api-secret-token", TELEGRAM_SECRET)
    .send({ update_id: 1, message: { chat: { id: -100123 }, from: { id: 555 }, text, ...extra } });
}

// ── authentication ──────────────────────────────────────────────────────────────────────

describe("authentication", () => {
  it("rejects a Slack request with a bad signature", async () => {
    const res = await request(app)
      .post("/integrations/slack/command")
      .set("content-type", "application/x-www-form-urlencoded")
      .set("x-slack-request-timestamp", String(Math.floor(Date.now() / 1000)))
      .set("x-slack-signature", "v0=deadbeef")
      .send("channel_id=C1&user_id=U1&text=status+c1");
    expect(res.status).toBe(401);
  });

  it("rejects a Slack request with no signature headers at all", async () => {
    const res = await request(app)
      .post("/integrations/slack/command")
      .set("content-type", "application/x-www-form-urlencoded")
      .send("channel_id=C1&user_id=U1&text=status+c1");
    expect(res.status).toBe(401);
  });

  it("accepts a correctly signed Slack request", async () => {
    expect((await slack("status c1")).status).toBe(200);
  });

  it("rejects a Teams request with a wrong or missing bearer token", async () => {
    expect((await request(app).post("/integrations/teams/command").set("authorization", "Bearer nope").send({ text: "status c1" })).status).toBe(401);
    expect((await request(app).post("/integrations/teams/command").send({ text: "status c1" })).status).toBe(401);
  });

  it("rejects a Telegram update with a wrong or missing secret token", async () => {
    expect((await request(app).post("/integrations/telegram/command").set("x-telegram-bot-api-secret-token", "nope").send({ message: { chat: { id: 1 }, text: "/status c1" } })).status).toBe(401);
    expect((await request(app).post("/integrations/telegram/command").send({ message: { chat: { id: 1 }, text: "/status c1" } })).status).toBe(401);
  });

  it("refuses every platform when its secret is not configured", async () => {
    vi.stubEnv("DFIR_SLACK_SIGNING_SECRET", "");
    vi.stubEnv("DFIR_TEAMS_TOKEN", "");
    vi.stubEnv("DFIR_TELEGRAM_SECRET_TOKEN", "");
    expect((await slack("status c1")).status).toBe(401);
    expect((await teams("status c1")).status).toBe(401);
    expect((await telegram("/status c1")).status).toBe(401);
  });
});

// ── rate limiting ───────────────────────────────────────────────────────────────────────

describe("rate limiting", () => {
  // The limit key comes from the request body, so limiting before authenticating would let an
  // unauthenticated caller burn a real war room's quota.
  it("does not spend the channel's budget on unauthenticated requests", async () => {
    for (let i = 0; i < 30; i++) {
      await request(app)
        .post("/integrations/slack/command")
        .set("content-type", "application/x-www-form-urlencoded")
        .set("x-slack-signature", "v0=deadbeef")
        .set("x-slack-request-timestamp", String(Math.floor(Date.now() / 1000)))
        .send("channel_id=C1&user_id=U1&text=status+c1");
    }
    expect((await slack("status c1")).status).toBe(200);
  });

  it("rate-limits an authenticated channel past the window cap", async () => {
    const codes: number[] = [];
    for (let i = 0; i < 22; i++) codes.push((await slack("status c1")).status);
    expect(codes.slice(0, 20).every((c) => c === 200)).toBe(true);
    expect(codes.at(-1)).toBe(429);
  });

  it("limits each channel separately", async () => {
    for (let i = 0; i < 21; i++) await slack("status c1");
    expect((await slack("status c1", { channel_id: "C2" })).status).toBe(200);
  });
});

// ── case guards ─────────────────────────────────────────────────────────────────────────

describe("case guards", () => {
  it("reports a missing case instead of a server error", async () => {
    const res = await slack("status nosuchcase");
    expect(res.status).toBe(200);
    expect(res.body.text).toMatch(/No such case: nosuchcase/);
  });

  // The case-password gate lives on /cases/:id; this route reads state directly, so without an
  // explicit check a locked case would be readable from chat with no unlock.
  it("refuses a password-protected case", async () => {
    await request(app).post("/cases/c1/password").send({ newPassword: "correct horse battery" });
    const res = await slack("findings c1");
    expect(res.status).toBe(200);
    expect(res.body.text).toMatch(/password-protected/);
    expect(res.body.text).not.toMatch(/finding/i);
  });

  it("refuses to bind a channel to a password-protected case", async () => {
    await request(app).post("/cases/c1/password").send({ newPassword: "correct horse battery" });
    const res = await slack("bind c1");
    expect(res.body.text).toMatch(/password-protected/);
    expect(await bindings.get("slack:C1")).toBeUndefined();
  });

  it("rejects a path-traversal caseId", async () => {
    const res = await slack("status ../../etc");
    expect(res.status).toBe(200);
    expect(res.body.text).toMatch(/valid caseId is required|No such case/);
  });
});

// ── binding + caseId resolution ─────────────────────────────────────────────────────────

describe("binding and caseId resolution", () => {
  it("binds, then answers commands with no caseId", async () => {
    expect((await slack("bind c1")).body.text).toMatch(/bound to case c1/);
    const res = await slack("status");
    expect(res.body.text).toMatch(/Status for c1/);
  });

  // The bug this suite exists for: `ask` used to swallow the question's first word as the caseId.
  it("keeps the whole question when a bound channel omits the caseId", async () => {
    await slack("bind c1");
    await slack("ask what was the initial access vector?");
    await vi.waitFor(() => expect(asked).toHaveLength(1));
    expect(asked[0]).toEqual({ caseId: "c1", question: "what was the initial access vector?" });
  });

  it("still honours an explicit caseId over the binding", async () => {
    await slack("bind c1");
    expect((await slack("status c2")).body.text).toMatch(/Status for c2/);
  });

  it("reads an ioc filter as a filter on a bound channel", async () => {
    await slack("bind c1");
    const res = await slack("iocs malicious");
    expect(res.body.text).toMatch(/IOCs for c1 \(malicious\)|IOC\(s\) \(malicious\)/);
  });

  it("unbind clears the binding and says what it was", async () => {
    await slack("bind c1");
    expect((await slack("unbind")).body.text).toMatch(/cleared \(was c1\)/);
    expect(await bindings.get("slack:C1")).toBeUndefined();
    expect((await slack("unbind")).body.text).toMatch(/not bound/);
  });

  it("asks for a caseId when the channel has no binding", async () => {
    expect((await slack("status")).body.text).toMatch(/valid caseId is required/);
  });
});

// ── access control ──────────────────────────────────────────────────────────────────────

describe("access control", () => {
  it("denies a privileged command to a user outside the allowlist", async () => {
    vi.stubEnv("DFIR_SLACK_ACTION_USERS", "admin");
    const res = await slack("synthesize c1");
    expect(res.status).toBe(200);
    expect(res.body.text).toMatch(/not permitted/);
  });

  it("allows a privileged command to an allowlisted user", async () => {
    vi.stubEnv("DFIR_SLACK_ACTION_USERS", "admin");
    expect((await slack("bind c1", { user_id: "admin" })).body.text).toMatch(/bound to case c1/);
  });

  // Without this, any chat member could read any case on the server just by naming it.
  it("confines a non-allowlisted user to the channel's bound case", async () => {
    vi.stubEnv("DFIR_SLACK_ACTION_USERS", "admin");
    await slack("bind c1", { user_id: "admin" });
    expect((await slack("status c1")).body.text).toMatch(/Status for c1/);
    expect((await slack("status c2")).body.text).toMatch(/may only use this channel's bound case/);
  });

  it("stays open when no allowlist is configured", async () => {
    expect((await slack("status c2")).body.text).toMatch(/Status for c2/);
    expect((await slack("bind c1")).body.text).toMatch(/bound to case c1/);
  });
});

// ── platform envelopes ──────────────────────────────────────────────────────────────────

describe("platform response envelopes", () => {
  it("answers Slack with a response_type envelope", async () => {
    const res = await slack("status c1");
    expect(res.body).toMatchObject({ response_type: "in_channel" });
    expect(res.body.text).toMatch(/Status for c1/);
  });

  it("answers Teams with a message envelope", async () => {
    const res = await teams("status c1");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ type: "message" });
    expect(res.body.text).toMatch(/Status for c1/);
  });

  it("answers Telegram with a sendMessage method envelope addressed to the chat", async () => {
    const res = await telegram("/status c1");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ method: "sendMessage", chat_id: "-100123" });
    expect(res.body.text).toMatch(/Status for c1/);
  });

  it("understands Telegram's @BotName command suffix", async () => {
    expect((await telegram("/status@DfirCompanionBot c1")).body.text).toMatch(/Status for c1/);
  });

  it("binds a Telegram chat independently of a Slack channel with the same id", async () => {
    await telegram("/bind c1");
    expect((await telegram("/status")).body.text).toMatch(/Status for c1/);
    expect(await bindings.get("telegram:-100123")).toMatchObject({ caseId: "c1" });
    expect(await bindings.get("slack:-100123")).toBeUndefined();
  });

  // Telegram retries a non-2xx webhook delivery, which would re-run the command; every
  // post-authentication reply must therefore be a 200 carrying the message.
  it("answers 200 even for a user-facing error", async () => {
    const res = await telegram("/status nosuchcase");
    expect(res.status).toBe(200);
    expect(res.body.text).toMatch(/No such case/);
  });
});

// ── async delivery ──────────────────────────────────────────────────────────────────────

describe("async command delivery", () => {
  const text = (i: number) => (delivered[i].body as { text: string }).text;

  it("ACKs ask immediately and posts the answer to the Slack response_url", async () => {
    const ack = await slack("ask c1 what happened?");
    expect(ack.status).toBe(200);
    expect(ack.body.text).toMatch(/Working on \/dfir ask for case c1/);

    await vi.waitFor(() => expect(delivered).toHaveLength(1));
    expect(delivered[0].url).toBe("https://hooks.slack.com/commands/T1/1/x");
    expect(text(0)).toMatch(/answer for c1/);
  });

  // The response_url is caller-supplied; delivering to it unchecked is a server-side request to
  // wherever the caller points.
  it("refuses to deliver to a response_url outside the platform's hosts", async () => {
    await slack("ask c1 what happened?", { response_url: "https://evil.example.com/collect" });
    await vi.waitFor(() => expect(asked).toHaveLength(1));
    expect(delivered).toEqual([]);
  });

  it("delivers a Telegram result through the Bot API", async () => {
    vi.stubEnv("DFIR_TELEGRAM_BOT_TOKEN", "12345:ABC");
    await telegram("/ask c1 what happened?");
    await vi.waitFor(() => expect(delivered).toHaveLength(1));
    expect(delivered[0].url).toBe("https://api.telegram.org/bot12345:ABC/sendMessage");
    expect(delivered[0].body).toMatchObject({ chat_id: "-100123" });
    expect(text(0)).toMatch(/answer for c1/);
  });

  it("drops a Telegram result rather than crashing when no bot token is configured", async () => {
    vi.stubEnv("DFIR_TELEGRAM_BOT_TOKEN", "");
    const ack = await telegram("/ask c1 what happened?");
    expect(ack.status).toBe(200);
    await vi.waitFor(() => expect(asked).toHaveLength(1));
    expect(delivered).toEqual([]);
  });

  it("hunt ACKs and hands off to the dashboard rather than claiming a deploy", async () => {
    await slack("hunt c1 T1059.001");
    await vi.waitFor(() => expect(delivered).toHaveLength(1));
    expect(text(0)).toMatch(/T1059\.001/);
    expect(text(0)).toMatch(/dashboard/);
  });
});

// ── audit trail ─────────────────────────────────────────────────────────────────────────

describe("activity log", () => {
  // logActivity is fire-and-forget, so the entry can land just after the response.
  const awaitAction = (caseId: string, action: string) =>
    vi.waitFor(async () => {
      const entry = (await activityLogStore.load(caseId)).find((e) => e.action === action);
      expect(entry, `no "${action}" entry for ${caseId}`).toBeDefined();
      return entry!;
    });

  it("logs a read-only command against the case", async () => {
    await slack("findings c1");
    const entry = await awaitAction("c1", "slash-command");
    expect(entry.detail).toContain("/dfir findings");
    expect(entry.actor).toBe("slack:U1");
  });

  it("logs bind and unbind", async () => {
    await slack("bind c1");
    await awaitAction("c1", "slash-command-bind");
    await slack("unbind");
    await awaitAction("c1", "slash-command-unbind");
  });

  it("logs a denied command as an error outcome", async () => {
    vi.stubEnv("DFIR_SLACK_ACTION_USERS", "admin");
    await slack("synthesize c1");
    expect((await awaitAction("c1", "slash-command-denied")).outcome).toBe("error");
  });

  it("does not write a log entry for a case that does not exist", async () => {
    vi.stubEnv("DFIR_SLACK_ACTION_USERS", "admin");
    const res = await slack("synthesize nosuchcase");
    expect(res.body.text).toMatch(/not permitted/);
    await expect(activityLogStore.load("nosuchcase")).resolves.toEqual([]);
  });
});

describe("registration", () => {
  it("does not register the routes when no binding store is configured", async () => {
    const bare = createApp(store, { stateStore });
    expect((await request(bare).post("/integrations/slack/command").send({})).status).toBe(404);
    expect((await request(bare).post("/integrations/telegram/command").send({})).status).toBe(404);
  });
});
