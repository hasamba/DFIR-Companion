import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { TelegramLimiters } from "../../../src/analysis/notify/telegramRateLimiter.js";
import { emptyWatsonChat, type WatsonTurn } from "../../../src/analysis/ai/watson/types.js";
import type { NotificationChannel, NotificationEvent } from "../../../src/analysis/notifications.js";
import { sendTelegramMessage } from "../../../src/analysis/telegramPoller.js";
import { dispatchEvent } from "../../../src/integrations/notify/notifyDispatch.js";
import { WatsonMirror, type TelegramSendGate } from "../../../src/integrations/telegram/watsonMirror.js";
import { workstationRoots } from "../../../src/integrations/telegram/watsonMirrorFormat.js";
import { sendMirrorMessage } from "../../../src/integrations/telegram/watsonMirrorSender.js";
import { WatsonMirrorStore } from "../../../src/integrations/telegram/watsonMirrorStore.js";

// #2711: the real senders — the Watson mirror service, the alert dispatcher and the command-reply
// sender — wired to ONE limiter registry, against a fake Bot API on real timers. The proof that an
// alert is never queued behind the mirror's backlog, end to end rather than inside the limiter.

const TOKEN = "4242:SECRET";
const CHAT = "-1001";
const quiet = { warn: () => {}, info: () => {}, error: () => {}, debug: () => {} } as never;

interface BotApi {
  fetchFn: typeof fetch;
  log: Array<{ kind: "mirror" | "alert" | "reply"; at: number }>;
}

function botApi(): BotApi {
  const log: BotApi["log"] = [];
  const fetchFn = (async (_url: string, init?: { body?: string }) => {
    const body = JSON.parse(init?.body ?? "{}");
    const text = String(body.text);
    // Alerts are HTML too: tell them apart by their title.
    const kind = text.includes("Cobalt Strike beacon")
      ? "alert"
      : body.parse_mode === "HTML"
        ? "mirror"
        : "reply";
    log.push({ kind, at: Date.now() });
    return Response.json({ ok: true, result: { message_id: log.length } });
  }) as unknown as typeof fetch;
  return { fetchFn, log };
}

function gateOf(registry: TelegramLimiters): TelegramSendGate {
  return {
    acquire: async (req) => ({ ...(await registry.forToken(TOKEN).acquire(req)), botToken: TOKEN }),
  };
}

async function mirrorWithBacklog(
  registry: TelegramLimiters,
  api: BotApi,
  over: Partial<ConstructorParameters<typeof WatsonMirror>[0]> = {},
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-shared-limiter-"));
  const store = new WatsonMirrorStore(join(root, "notifications", "watson-mirror.json"));
  await store.enable(CHAT, {
    caseId: "c1",
    chatType: "supergroup",
    by: "42",
    boundAt: "b1",
    at: new Date(Date.now() - 1_000).toISOString(),
  });
  // One long answer: the formatter splits it into several messages, sent in order.
  const turn: WatsonTurn = {
    id: "wt-1",
    at: new Date().toISOString(),
    role: "watson",
    text: Array.from(
      { length: 300 },
      (_, i) => `line ${i} of a long Watson answer about lateral movement`,
    ).join("\n"),
  };
  const mirror = new WatsonMirror({
    store,
    loadChat: async () => ({ ...emptyWatsonChat(), turns: [turn] }),
    loadHistory: async () => ({ turns: [turn], more: false }),
    liveness: async () => ({ ok: true }),
    masking: async (_c, raw) => ({ ok: true, text: raw }),
    send: (chatId, text, botToken) =>
      sendMirrorMessage({ botToken: botToken ?? TOKEN, chatId, text, fetchFn: api.fetchFn }),
    limiter: gateOf(registry),
    audit: () => {},
    roots: workstationRoots({ casesRoot: "/srv/dfir/cases", dataDir: "/srv/dfir", installDirs: [] }),
    publicUrl: () => undefined,
    log: quiet,
    ...over,
  });
  return mirror;
}

const alertChannel: NotificationChannel = {
  id: "tg",
  name: "War room",
  type: "telegram",
  enabled: true,
  minSeverity: "Info",
  events: { critical_finding: true },
  telegram: { botToken: TOKEN, chatId: CHAT },
} as unknown as NotificationChannel;

const alertEvent: NotificationEvent = {
  kind: "critical_finding",
  caseId: "c1",
  severity: "Critical",
  title: "Alert: Cobalt Strike beacon on HOST-7",
  lines: [],
  at: new Date().toISOString(),
} as unknown as NotificationEvent;

const until = async (cond: () => boolean, ms = 8_000) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
};

describe("one Telegram limiter shared by the mirror, alerts and replies (#2711)", () => {
  it("an alert to a chat with a mirror backlog is the very next message Telegram receives there", async () => {
    const registry = new TelegramLimiters();
    const api = botApi();
    const mirror = await mirrorWithBacklog(registry, api);
    try {
      void mirror.notify("c1");
      await until(() => api.log.length >= 1); // the first mirror message is out; the rest wait 1 s each
      const results = dispatchEvent([alertChannel], alertEvent, {
        fetchFn: api.fetchFn,
        telegramLimiters: registry,
      });
      const sent = await results;
      expect(sent[0].ok).toBe(true);
      await until(() => api.log.filter((e) => e.kind === "mirror").length >= 3);
      expect(api.log.slice(0, 3).map((e) => e.kind)).toEqual(["mirror", "alert", "mirror"]);
      // The alert waited only the 1 s spacing after the mirror message before it.
      expect(api.log[1].at - api.log[0].at).toBeLessThan(1_500);
      // And the next mirror message kept the spacing after the alert.
      expect(api.log[2].at - api.log[1].at).toBeGreaterThanOrEqual(990);
    } finally {
      mirror.stop();
    }
  }, 15_000);

  it("a command reply goes before the mirror's backlog too, and after nothing but spacing", async () => {
    const registry = new TelegramLimiters();
    const api = botApi();
    const mirror = await mirrorWithBacklog(registry, api);
    try {
      void mirror.notify("c1");
      await until(() => api.log.length >= 1);
      await sendTelegramMessage({
        botToken: TOKEN,
        chatId: CHAT,
        text: "Bound this chat to case c1.",
        fetchFn: api.fetchFn,
        log: quiet,
        limiters: registry,
      });
      await until(() => api.log.filter((e) => e.kind === "mirror").length >= 2);
      expect(api.log.slice(0, 3).map((e) => e.kind)).toEqual(["mirror", "reply", "mirror"]);
    } finally {
      mirror.stop();
    }
  }, 15_000);

  it("a 429 drawn by one sender pauses the others on the same bot", async () => {
    const registry = new TelegramLimiters();
    const at: number[] = [];
    let first = true;
    const fetchFn = (async () => {
      at.push(Date.now());
      if (first) {
        first = false;
        return Response.json({ ok: false, parameters: { retry_after: 1 } }, { status: 429 });
      }
      return Response.json({ ok: true, result: { message_id: 1 } });
    }) as unknown as typeof fetch;
    // A reply draws the 429 and is retried after it…
    const reply = sendTelegramMessage({
      botToken: TOKEN,
      chatId: "77",
      text: "hi",
      fetchFn,
      log: quiet,
      limiters: registry,
    });
    await until(() => at.length >= 1);
    // …and an alert to ANOTHER chat on the same bot waits the pause out as well.
    const alert = dispatchEvent(
      [{ ...alertChannel, telegram: { botToken: TOKEN, chatId: "88" } }],
      alertEvent,
      {
        fetchFn,
        telegramLimiters: registry,
      },
    );
    await Promise.all([reply, alert]);
    expect(at).toHaveLength(3);
    expect(at[1] - at[0]).toBeGreaterThanOrEqual(990);
    expect(at[2] - at[0]).toBeGreaterThanOrEqual(990);
  }, 10_000);

  it("the mirror releases a slot it may no longer use, and a 429 it draws pauses the bot", async () => {
    for (const authorized of [false, true]) {
      const calls: string[] = [];
      let checks = 0;
      const gate: TelegramSendGate = {
        acquire: async () => ({
          commit: () => (calls.push("commit"), true),
          release: () => void calls.push("release"),
          backOff: (ms: number) => void calls.push(`backOff ${ms}`),
          botToken: TOKEN,
        }),
      };
      const mirror = await mirrorWithBacklog(new TelegramLimiters(), botApi(), {
        limiter: gate,
        // The flush's own check passes; the re-check after the slot wait is the one that may fail.
        liveness: async () =>
          authorized || ++checks === 1 ? { ok: true } : { ok: false, action: "pause", reason: "archived" },
        send: async () => ({ kind: "rate_limited", retryAfterMs: 7_000 }),
      });
      try {
        await mirror.notify("c1");
        await until(() => calls.length >= (authorized ? 2 : 1));
        // Unauthorized after the wait: the slot goes back unused. Authorized: sent, and the 429 pauses the bot.
        expect(calls).toEqual(authorized ? ["commit", "backOff 7000"] : ["release"]);
      } finally {
        mirror.stop();
      }
    }
  });
});
