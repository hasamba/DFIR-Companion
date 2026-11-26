import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AiControlStore } from "../../src/analysis/aiControl.js";
import { SlashCommandChannelStore } from "../../src/analysis/slashCommandStore.js";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { sharedTelegramLimiters } from "../../src/analysis/notify/telegramRateLimiter.js";
import { createApp } from "../../src/server.js";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import type { WatsonProposal } from "../../src/analysis/ai/watson/types.js";
import { WatsonMirrorStore } from "../../src/integrations/telegram/watsonMirrorStore.js";
import { parseMirrorCallback } from "../../src/integrations/telegram/watsonMirrorActions.js";
import { createWatsonMirrorLink } from "../../src/composition/watsonMirrorWiring.js";
import { resetMirrorPressLimiter, TOAST } from "../../src/routes/watsonMirrorCallback.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";

// #2712 end to end through createApp and a mock Bot API: a mirrored Watson proposal carries Apply /
// Reject buttons; a press from an allowlisted user in the bound, mirroring chat decides it through the
// dashboard's own path, recorded as "<name> (via Telegram)"; every other press is refused with a toast.

const SECRET = "telegram-secret";
const CHAT = 555;
const LISTED = "555";
const ALICE = { id: 555, username: "alice_ir", first_name: "Alice" };

let store: CaseStore;
let chatStore: WatsonChatStore;
let mirrors: WatsonMirrorStore;
let mirrorFile: string;
let activity: ActivityLogStore;
let stateStore: StateStore;
let app: ReturnType<typeof createApp>;
let sent: Array<{
  chat_id: string;
  text: string;
  reply_markup?: { inline_keyboard: Array<Array<{ callback_data: string }>> };
}>;
let updateId = 0;
let callbackId = 0;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-mirrorcb-"));
  store = new CaseStore(join(root, "cases"));
  for (const id of ["c1", "c2"]) {
    await store.createCase({ caseId: id, name: id, investigator: "i", aiProvider: null });
    await new AiControlStore(store).save(id, { enabled: true, lastAnalyzedSeq: 0 });
  }
  chatStore = new WatsonChatStore(store);
  mirrorFile = join(root, "notifications", "watson-mirror.json");
  mirrors = new WatsonMirrorStore(mirrorFile);
  activity = new ActivityLogStore(store);
  stateStore = new StateStore(store);
  sent = [];
  vi.stubGlobal("fetch", async (url: string, init?: { body?: string }) => {
    if (url.endsWith("/getMe")) return Response.json({ ok: true, result: { username: "DfirBot" } });
    const body = JSON.parse(init?.body ?? "{}");
    sent.push({ chat_id: String(body.chat_id), text: String(body.text), reply_markup: body.reply_markup });
    return Response.json({ ok: true, result: { message_id: 9000 + sent.length } });
  });
  vi.stubEnv("DFIR_TELEGRAM_SECRET_TOKEN", SECRET);
  vi.stubEnv("DFIR_TELEGRAM_BOT_TOKEN", "1:T");
  vi.stubEnv("DFIR_TELEGRAM_ACTION_USERS", `${LISTED},777`);
  resetLimiters();
  resetMirrorPressLimiter();
  sharedTelegramLimiters.reset();
  const link = createWatsonMirrorLink();
  app = createApp(store, {
    stateStore,
    stateLock: new StateLock(),
    activityLogStore: activity,
    slashCommandChannelStore: new SlashCommandChannelStore(join(root, "notifications", "bindings.json")),
    watsonMirrorStore: mirrors,
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

const post = (body: Record<string, unknown>) =>
  request(app)
    .post("/integrations/telegram/command")
    .set("x-telegram-bot-api-secret-token", SECRET)
    .send({ update_id: ++updateId, ...body });

const say = (text: string, chat = CHAT) =>
  post({ message: { message_id: ++updateId, chat: { id: chat, type: "private" }, from: { id: 555 }, text } });

function press(data: string, opts: { from?: Record<string, unknown>; chat?: number; id?: string } = {}) {
  return post({
    callback_query: {
      id: opts.id ?? `cb-${++callbackId}`,
      from: opts.from ?? ALICE,
      message: { message_id: 1, chat: { id: opts.chat ?? CHAT, type: "private" } },
      data,
    },
  });
}

const toast = (res: { body: Record<string, unknown> }) => {
  expect(res.body.method).toBe("answerCallbackQuery");
  return res.body.text;
};

const finding = (id = "wp-f", extra: Record<string, unknown> = {}): WatsonProposal =>
  ({
    id,
    turnId: "wt-w",
    status: "pending",
    kind: "finding_new",
    targetId: `f-${id}`,
    after: { id: `f-${id}`, title: "Beacon to 203.0.113.9", severity: "High", description: "C2 traffic" },
    pasteLineEvents: [],
    ...extra,
  }) as unknown as WatsonProposal;

const step = (id = "wp-s"): WatsonProposal =>
  ({
    id,
    turnId: "wt-w",
    status: "pending",
    kind: "next_step_new",
    targetId: `ns-${id}`,
    after: {
      id: `ns-${id}`,
      priority: "high",
      action: "Pull Security.evtx on HOST-1",
      rationale: "r",
      pointer: "p",
    },
  }) as unknown as WatsonProposal;

/** Bind, mirror on, then a Watson turn with the proposals; returns the buttons' tokens by proposal. */
async function mirroredProposals(proposals: WatsonProposal[]): Promise<Record<string, string>> {
  await say("/dfir bind c1");
  expect((await say("/dfir mirror on")).body).toEqual({});
  const entry = await vi.waitFor(async () => {
    const e = await mirrors.get(String(CHAT));
    expect(e?.messageIds.length).toBe(1); // "Mirroring started" went out
    return e!;
  });
  await chatStore.update("c1", (c) => ({
    ...c,
    turns: [
      ...c.turns,
      {
        id: "wt-w",
        at: new Date().toISOString(),
        role: "watson",
        text: "Found it",
        proposalIds: proposals.map((p) => p.id),
      },
    ],
    proposals: [...c.proposals, ...proposals],
  }));
  app.locals.watsonMirror?.notify("c1");
  const withButtons = await vi.waitFor(
    () => {
      const m = sent.find((s) => s.text.includes("Found it"));
      expect(m).toBeDefined();
      return m!;
    },
    { timeout: 3_000 },
  );
  expect(entry.caseId).toBe("c1");
  const tokens: Record<string, string> = {};
  for (const row of withButtons.reply_markup?.inline_keyboard ?? []) {
    const { token } = parseMirrorCallback(row[0].callback_data)!;
    tokens[(await mirrors.findAction(token))!.proposalId] = token;
  }
  return tokens;
}

const proposalOf = async (id: string) => (await chatStore.load("c1")).proposals.find((p) => p.id === id);

describe("Telegram proposal buttons (#2712)", () => {
  it("applies through the dashboard's path, recorded as the Telegram user, and mirrors the result", async () => {
    const { "wp-s": token } = await mirroredProposals([step()]);
    expect(token).toBeDefined();
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.applied);

    const p = await proposalOf("wp-s");
    expect(p).toMatchObject({ status: "applied", appliedBy: "@alice_ir (via Telegram)" });
    const state = await stateStore.load("c1");
    expect(state.nextSteps.some((n) => n.action === "Pull Security.evtx on HOST-1")).toBe(true);
    const log = await activity.load("c1");
    const applied = log.find((e) => e.action === "watson.apply");
    expect(applied?.actor).toBe("@alice_ir (via Telegram)");
    expect(applied?.detail).toContain("Telegram user 555");

    // The decision reaches the chat as a normal mirrored turn: a system note naming the change.
    const note = (await chatStore.load("c1")).turns.at(-1);
    expect(note).toMatchObject({ role: "system", actor: "@alice_ir (via Telegram)" });
    expect(note?.text).toMatch(/^Applied Watson's next step: Pull Security\.evtx/);
    expect(note?.text).not.toContain("alice");
  });

  it("answers 'the case changed' when the writer refuses (a finding whose evidence is gone)", async () => {
    const { "wp-f": token } = await mirroredProposals([finding()]);
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.changed);
    expect((await proposalOf("wp-f"))?.status).toBe("pending");
  });

  it("rejects, and a stale button (already decided) is refused", async () => {
    const tokens = await mirroredProposals([finding("wp-1"), finding("wp-2")]);
    expect(toast(await press(`wm:r:${tokens["wp-1"]}`))).toBe(TOAST.rejected);
    expect((await proposalOf("wp-1"))?.status).toBe("rejected");
    expect(toast(await press(`wm:a:${tokens["wp-1"]}`))).toBe(TOAST.decided);
    expect((await proposalOf("wp-1"))?.status).toBe("rejected");
    // Decided in the dashboard meanwhile.
    await request(app).post("/cases/c1/watson/proposals/wp-2/reject").send({});
    expect(toast(await press(`wm:a:${tokens["wp-2"]}`))).toBe(TOAST.decided);
  });

  it("refuses a user not on the allowlist, and everyone when the allowlist is empty", async () => {
    const { "wp-f": token } = await mirroredProposals([finding()]);
    expect(toast(await press(`wm:a:${token}`, { from: { id: 999, username: "mallory" } }))).toBe(
      TOAST.notAllowed,
    );
    expect((await proposalOf("wp-f"))?.status).toBe("pending");
    expect((await activity.load("c1")).some((e) => e.action === "slash-command-denied")).toBe(true);
    vi.stubEnv("DFIR_TELEGRAM_ACTION_USERS", "");
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.notAllowed);
    expect((await proposalOf("wp-f"))?.status).toBe("pending");
  });

  it("refuses once the chat is unbound or stops mirroring", async () => {
    const { "wp-f": token } = await mirroredProposals([finding()]);
    await say("/dfir mirror off");
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.expired);
    await say("/dfir mirror on"); // a new enablement: the old buttons stay dead
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.expired);
    await say("/dfir unbind");
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.expired);
    expect((await proposalOf("wp-f"))?.status).toBe("pending");
  });

  it("refuses an archived, closed or password-protected case", async () => {
    const { "wp-f": token } = await mirroredProposals([finding()]);
    await store.updateCaseMeta("c1", { status: "archived" });
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.unavailable);
    await store.updateCaseMeta("c1", { status: "closed" });
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.unavailable);
    await store.updateCaseMeta("c1", {
      status: "open",
      password: await hashCasePassword("correct horse battery"),
    });
    const res = toast(await press(`wm:a:${token}`));
    expect([TOAST.unavailable, TOAST.expired]).toContain(res); // the mirror may have switched off already
    expect((await proposalOf("wp-f"))?.status).toBe("pending");
  });

  it("refuses forged data, unknown tokens and a token pressed in another chat", async () => {
    const { "wp-f": token } = await mirroredProposals([finding()]);
    expect(toast(await press("wm:u:" + token))).toBe(TOAST.invalid);
    expect(toast(await press("apply wp-f"))).toBe(TOAST.invalid);
    expect(toast(await press("wm:a:AAAAAAAAAAAAAAAA"))).toBe(TOAST.expired);
    expect(toast(await press(`wm:a:${token}`, { chat: -100777 }))).toBe(TOAST.expired);
    expect((await proposalOf("wp-f"))?.status).toBe("pending");
  });

  it("treats a pre-upgrade 96-bit button as expired, even on a pending proposal (#2897)", async () => {
    await mirroredProposals([finding()]);
    const saved = JSON.parse(await readFile(mirrorFile, "utf8"));
    const legacy = "L".repeat(16);
    saved.chats[String(CHAT)].actions.push({ token: legacy, proposalId: "wp-f" });
    await writeFile(mirrorFile, JSON.stringify(saved));
    expect(toast(await press(`wm:a:${legacy}`))).toBe(TOAST.expired);
    expect(toast(await press(`wm:r:${legacy}`))).toBe(TOAST.expired);
    expect((await proposalOf("wp-f"))?.status).toBe("pending");
  });

  it("refuses an ineligible stored kind even with a valid token", async () => {
    const { after } = finding() as Extract<WatsonProposal, { kind: "finding_new" }>;
    const change = finding("wp-v", { kind: "finding_update", before: after });
    await mirroredProposals([finding(), change]);
    const entry = await mirrors.get(String(CHAT));
    // A token for the launch, as if forged into the store: the press reads the kind from the chat store.
    const { "wp-v": token } = await mirrors.actionTokens(String(CHAT), entry!.enabledAt, ["wp-v"]);
    expect(toast(await press(`wm:a:${token}`))).toBe(TOAST.dashboardOnly);
    expect((await proposalOf("wp-v"))?.status).toBe("pending");
  });

  it("decides once for a replayed callback", async () => {
    const { "wp-s": token } = await mirroredProposals([step()]);
    expect(toast(await press(`wm:a:${token}`, { id: "same" }))).toBe(TOAST.applied);
    expect(toast(await press(`wm:a:${token}`, { id: "same" }))).toBe(TOAST.replay);
    const applies = (await activity.load("c1")).filter((e) => e.action === "watson.apply");
    expect(applies).toHaveLength(1);
  });

  it("answers nothing for a callback with no id, and refuses an unauthenticated webhook", async () => {
    const res = await post({ callback_query: { data: "wm:a:AAAAAAAAAAAAAAAA" } });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({});
    const forged = await request(app)
      .post("/integrations/telegram/command")
      .set("x-telegram-bot-api-secret-token", "wrong-secret-value")
      .send({ update_id: 1, callback_query: { id: "x", data: "wm:a:AAAAAAAAAAAAAAAA" } });
    expect(forged.status).toBe(401);
  });
});
