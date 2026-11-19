import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { createApp } from "../../src/server.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import type { WatsonChat } from "../../src/analysis/ai/watson/types.js";
import type { WatsonRoundInput } from "../../src/analysis/ai/watson/pipelineRound.js";
import { WatsonMirrorStore } from "../../src/integrations/telegram/watsonMirrorStore.js";
import { createWatsonMirrorLink } from "../../src/composition/watsonMirrorWiring.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";

// #2647 end to end through createApp and a mock Bot API (stubbed fetch): `/dfir mirror on|off`, plain-
// text questions (private chats, group mentions and replies), inbound dedup, refusals, the "Asking
// Watson…" ack with exactly one answer, revocation on unbind, and the Watson panel's list and Off.

const SECRET = "telegram-secret";
const PRIVATE = 555; // a private chat's id equals the user's id
const GROUP = -100123;
const LISTED = "555";

let store: CaseStore;
let chatStore: WatsonChatStore;
let bindings: SlashCommandChannelStore;
let mirrors: WatsonMirrorStore;
let app: ReturnType<typeof createApp>;
let asked: Array<{ caseId: string; text: string }>;
let sent: Array<{ chat_id: string; text: string; message_id: number }>;
let updateId = 0;

const fakePipeline = {
  watsonRound: async (caseId: string, input: WatsonRoundInput): Promise<WatsonChat> => {
    asked.push({ caseId, text: input.text });
    const at = new Date().toISOString();
    return chatStore.update(caseId, (c) => ({
      ...c,
      turns: [
        ...c.turns,
        { id: `wt-a${asked.length}`, at, role: "analyst", text: input.text, actor: input.actor },
        { id: `wt-w${asked.length}`, at, role: "watson", text: `answer about ${caseId}` },
      ],
    }));
  },
} as unknown as import("../../src/analysis/pipeline.js").AnalysisPipeline;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-mirrorroute-"));
  store = new CaseStore(join(root, "cases"));
  for (const id of ["c1", "c2"]) {
    await store.createCase({ caseId: id, name: id, investigator: "i", aiProvider: null });
    await new AiControlStore(store).save(id, { enabled: true, lastAnalyzedSeq: 0 });
  }
  chatStore = new WatsonChatStore(store);
  bindings = new SlashCommandChannelStore(join(root, "notifications", "slash-command-bindings.json"));
  mirrors = new WatsonMirrorStore(join(root, "notifications", "watson-mirror.json"));
  asked = [];
  sent = [];
  vi.stubGlobal("fetch", async (url: string, init?: { body?: string }) => {
    if (url.endsWith("/getMe")) return Response.json({ ok: true, result: { username: "DfirBot" } });
    const body = JSON.parse(init?.body ?? "{}");
    const message_id = 9000 + sent.length;
    sent.push({ chat_id: String(body.chat_id), text: String(body.text), message_id });
    return Response.json({ ok: true, result: { message_id } });
  });
  vi.stubEnv("DFIR_TELEGRAM_SECRET_TOKEN", SECRET);
  vi.stubEnv("DFIR_TELEGRAM_BOT_TOKEN", "1:T");
  vi.stubEnv("DFIR_TELEGRAM_ACTION_USERS", LISTED);
  resetLimiters();
  const link = createWatsonMirrorLink();
  app = createApp(store, {
    stateStore: new StateStore(store),
    activityLogStore: new ActivityLogStore(store),
    slashCommandChannelStore: bindings,
    watsonMirrorStore: mirrors,
    pipeline: fakePipeline,
    watsonChatStore: chatStore,
    watsonProvider: () => ({ name: "fake", model: "fake-model", analyze: async () => ({ rawText: "{}" }) }),
    onWatson: (caseId) => link.notify(caseId),
    onWatsonMirrorReady: link.attach,
  });
});

afterEach(() => {
  app.locals.watsonMirror?.stop();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

function tg(message: Record<string, unknown>, opts: { chat?: number; type?: string; from?: number } = {}) {
  const chat = opts.chat ?? PRIVATE;
  return request(app)
    .post("/integrations/telegram/command")
    .set("x-telegram-bot-api-secret-token", SECRET)
    .send({
      update_id: ++updateId,
      message: {
        message_id: updateId,
        chat: { id: chat, type: opts.type ?? (chat < 0 ? "supergroup" : "private") },
        from: { id: opts.from ?? 555 },
        ...message,
      },
    });
}

async function mirrorOn(chat = PRIVATE, caseId = "c1") {
  await tg({ text: `/dfir bind ${caseId}` }, { chat });
  const res = await tg({ text: "/dfir mirror on" }, { chat });
  expect(res.body.text).toMatch(/Mirroring started for case c1/);
}

const toChat = (chat: number) => sent.filter((s) => s.chat_id === String(chat));
const settle = () => new Promise((r) => setTimeout(r, 30));

describe("/dfir mirror on|off", () => {
  it("is refused while the Telegram allowlist is empty, and for an unlisted user", async () => {
    await tg({ text: "/dfir bind c1" });
    vi.stubEnv("DFIR_TELEGRAM_ACTION_USERS", "");
    expect((await tg({ text: "/dfir mirror on" })).body.text).toMatch(/needs the Telegram user allowlist/);
    vi.stubEnv("DFIR_TELEGRAM_ACTION_USERS", "777");
    expect((await tg({ text: "/dfir mirror on" })).body.text).toMatch(/not permitted/);
    expect(await mirrors.get(String(PRIVATE))).toBeUndefined();
  });

  it("needs a bound chat, then turns on and off", async () => {
    expect((await tg({ text: "/dfir mirror on" })).body.text).toMatch(/Bind this chat/);
    await mirrorOn();
    expect(await mirrors.get(String(PRIVATE))).toMatchObject({ caseId: "c1", enabledBy: LISTED });
    expect((await tg({ text: "/dfir mirror off" })).body.text).toMatch(/Mirroring stopped for case c1/);
    expect(await mirrors.get(String(PRIVATE))).toBeUndefined();
  });

  it("stops mirroring when the chat is unbound or bound to another case (AC14)", async () => {
    await mirrorOn();
    await tg({ text: "/dfir unbind" });
    expect(await mirrors.get(String(PRIVATE))).toBeUndefined();
    await mirrorOn();
    await tg({ text: "/dfir bind c2" });
    expect(await mirrors.get(String(PRIVATE))).toBeUndefined();
  });
});

describe("plain-text questions", () => {
  it("runs one round on the bound case, acks, answers once and never echoes the question (AC4)", async () => {
    await mirrorOn();
    const before = sent.length;
    const res = await tg({ text: "c2 what ran   on the host?" });
    expect(res.body.text).toBe("Asking Watson…");
    await vi.waitFor(() => expect(toChat(PRIVATE).length).toBe(before + 1));
    await settle();
    expect(asked).toEqual([{ caseId: "c1", text: "c2 what ran   on the host?" }]);
    const out = sent.slice(before);
    expect(out).toHaveLength(1);
    expect(out[0].text).toContain("answer about c1");
    expect(out[0].text).not.toContain("what ran");
  });

  it("ignores group chatter and replies to non-mirror messages, with no round (AC5)", async () => {
    await mirrorOn(GROUP);
    const chatter = await tg({ text: "lunch?" }, { chat: GROUP });
    expect(chatter.status).toBe(200);
    expect(chatter.body).toEqual({});
    await tg({ text: "is this bad?", reply_to_message: { message_id: 1 } }, { chat: GROUP });
    await settle();
    expect(asked).toEqual([]);
  });

  it("answers a group mention and a reply to a mirrored message", async () => {
    await mirrorOn(GROUP);
    await tg(
      { text: "@DfirBot who logged on?", entities: [{ type: "mention", offset: 0, length: 8 }] },
      { chat: GROUP },
    );
    await vi.waitFor(() => expect(toChat(GROUP).length).toBe(1));
    expect(asked[0]).toEqual({ caseId: "c1", text: "who logged on?" });
    await tg(
      { text: "and then?", reply_to_message: { message_id: toChat(GROUP)[0].message_id } },
      { chat: GROUP },
    );
    await vi.waitFor(() => expect(asked).toHaveLength(2));
  });

  it("refuses an unlisted user and a password-protected case with the existing sentences (AC6)", async () => {
    await mirrorOn();
    expect((await tg({ text: "hi" }, { from: 777 })).body.text).toMatch(/not permitted to run \/dfir ask/);
    await store.updateCaseMeta("c1", { password: await hashCasePassword("correct horse battery") });
    expect((await tg({ text: "hi" })).body.text).toMatch(/password-protected/);
    expect(asked).toEqual([]);
  });

  it("runs one round for an update delivered twice (AC7)", async () => {
    await mirrorOn();
    const body = {
      update_id: 50,
      message: { message_id: 50, chat: { id: PRIVATE, type: "private" }, from: { id: 555 }, text: "once?" },
    };
    for (let i = 0; i < 2; i++)
      await request(app)
        .post("/integrations/telegram/command")
        .set("x-telegram-bot-api-secret-token", SECRET)
        .send(body);
    await vi.waitFor(() => expect(asked).toHaveLength(1));
    await settle();
    expect(asked).toHaveLength(1);
  });

  it("gives /dfir ask in a mirroring chat the short ack and one answer through the mirror", async () => {
    await mirrorOn();
    const before = sent.length;
    expect((await tg({ text: "/dfir ask what ran?" })).body.text).toBe("Asking Watson…");
    await vi.waitFor(() => expect(sent.length).toBe(before + 1));
    await settle();
    expect(sent.slice(before).map((s) => s.text.includes("answer about c1"))).toEqual([true]);
  });

  it("mirrors a dashboard question with link previews off", async () => {
    await mirrorOn();
    const before = sent.length;
    await fakePipeline.watsonRound("c1", { text: "dashboard q", actor: "ana" } as WatsonRoundInput);
    app.locals.watsonMirror.notify("c1");
    await vi.waitFor(() => expect(sent.length).toBe(before + 1));
    expect(sent[before].text).toContain("dashboard q");
  });
});

describe("the Watson panel list", () => {
  it("lists the mirroring chats and switches one off; there is no on route (AC3)", async () => {
    await mirrorOn();
    const list = await request(app).get("/cases/c1/watson/mirrors");
    expect(list.body.mirrors).toEqual([expect.objectContaining({ chatId: String(PRIVATE), held: false })]);
    expect((await request(app).get("/cases/c2/watson/mirrors")).body.mirrors).toEqual([]);
    expect((await request(app).post(`/cases/c2/watson/mirrors/${PRIVATE}/off`)).status).toBe(404);
    expect((await request(app).post(`/cases/c1/watson/mirrors/${PRIVATE}/on`)).status).toBe(404);
    expect((await request(app).post(`/cases/c1/watson/mirrors/${PRIVATE}/off`)).status).toBe(200);
    expect(await mirrors.get(String(PRIVATE))).toBeUndefined();
  });
});
