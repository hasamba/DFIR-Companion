import { describe, it, expect, vi } from "vitest";
import {
  TelegramPoller,
  sendTelegramMessage,
  type TelegramUpdate,
} from "../../src/analysis/telegramPoller.js";
import type { Logger } from "../../src/logging/logger.js";

// The long-poll transport (#235): the Companion calls Telegram rather than being called, so
// Telegram commands need no tunnel, no DFIR_ALLOWED_HOSTS entry and no setWebhook.

// Yield to the event loop on every retry. A sleep stub that resolves instantly turns the retry
// loop into a tight spin that starves vi.waitFor — the real sleep is a setTimeout, so it always
// yields.
const yieldingSleep = (record?: number[]) => async (ms: number) => {
  record?.push(ms);
  await new Promise((r) => setTimeout(r, 1));
};

function fakeLog(): Logger & { lines: string[] } {
  const lines: string[] = [];
  const push = (level: string) => (m: string) => {
    lines.push(`${level} ${m}`);
  };
  return {
    lines,
    debug: push("debug"),
    info: push("info"),
    warn: push("warn"),
    error: push("error"),
    getLevel: () => "info",
    setLevel: () => {},
    close: async () => {},
  } as unknown as Logger & { lines: string[] };
}

const message = (id: number, text: string): TelegramUpdate => ({
  update_id: id,
  message: { chat: { id: -100 }, from: { id: 7 }, text },
});

/** A fetch stub that serves queued getUpdates rounds, then blocks so the loop parks. */
function fetchServing(rounds: Array<{ status?: number; body: unknown }>) {
  const urls: string[] = [];
  const fn = async (url: string, init?: { signal?: AbortSignal }) => {
    urls.push(String(url));
    const next = rounds.shift();
    if (!next) {
      // Nothing left to serve: park until the poller aborts, mimicking Telegram holding the line.
      await new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    }
    return new Response(JSON.stringify(next!.body), { status: next!.status ?? 200 });
  };
  return { fn: fn as unknown as typeof fetch, urls };
}

describe("TelegramPoller", () => {
  it("delivers each update to the handler", async () => {
    const seen: string[] = [];
    const { fn } = fetchServing([
      { body: { ok: true, result: [message(1, "/dfir status"), message(2, "/dfir findings")] } },
    ]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async (u) => {
        seen.push(u.message?.text ?? "");
      },
    });
    poller.start();
    await vi.waitFor(() => expect(seen).toHaveLength(2));
    await poller.stop();
    expect(seen).toEqual(["/dfir status", "/dfir findings"]);
  });

  // The offset is what marks updates delivered. Without it Telegram replays the same commands on
  // every poll, forever.
  it("advances the offset past the updates it has handled", async () => {
    const { fn, urls } = fetchServing([
      { body: { ok: true, result: [message(10, "/dfir status"), message(11, "/dfir help")] } },
      { body: { ok: true, result: [] } },
    ]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
    });
    poller.start();
    await vi.waitFor(() => expect(urls.length).toBeGreaterThanOrEqual(2));
    await poller.stop();
    expect(urls[0]).not.toContain("offset="); // first call has no cursor yet
    expect(urls[1]).toContain("offset=12"); // 11 + 1
  });

  // One malformed command must not wedge the bot, and must not be redelivered forever.
  it("keeps polling when a handler throws, and does not replay that update", async () => {
    const { fn, urls } = fetchServing([
      { body: { ok: true, result: [message(5, "/dfir boom")] } },
      { body: { ok: true, result: [] } },
    ]);
    const log = fakeLog();
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log,
      onUpdate: async () => {
        throw new Error("handler exploded");
      },
    });
    poller.start();
    await vi.waitFor(() => expect(urls.length).toBeGreaterThanOrEqual(2));
    await poller.stop();
    expect(urls[1]).toContain("offset=6");
    expect(log.lines.some((l) => l.includes("handler exploded"))).toBe(true);
  });

  // The caller passes `apiBase: undefined` whenever DFIR_TELEGRAM_API_BASE is unset. Spreading
  // options over a defaults object let that undefined win, and every poll died on
  // "Cannot read properties of undefined (reading 'replace')" — invisible to any test that simply
  // omits the key, which is what all the others here do.
  it("falls back to the public Bot API when apiBase is explicitly undefined", async () => {
    const { fn, urls } = fetchServing([{ body: { ok: true, result: [] } }]);
    const poller = new TelegramPoller({
      botToken: "T",
      apiBase: undefined,
      pollTimeoutSeconds: undefined,
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
    });
    poller.start();
    await vi.waitFor(() => expect(urls.length).toBeGreaterThanOrEqual(1));
    await poller.stop();
    expect(urls[0]).toContain("https://api.telegram.org/botT/getUpdates");
    expect(urls[0]).toContain("timeout=50");
  });

  it("requests only message updates, with a long-poll timeout", async () => {
    const { fn, urls } = fetchServing([{ body: { ok: true, result: [] } }]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
    });
    poller.start();
    await vi.waitFor(() => expect(urls.length).toBeGreaterThanOrEqual(1));
    await poller.stop();
    expect(urls[0]).toContain("/botT/getUpdates");
    expect(urls[0]).toContain("timeout=50");
    expect(urls[0]).toContain("message");
  });

  it("backs off after a failure and retries", async () => {
    const slept: number[] = [];
    const { fn, urls } = fetchServing([
      { status: 500, body: { ok: false, description: "server error" } },
      { body: { ok: true, result: [] } },
    ]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
      sleepFn: yieldingSleep(slept),
    });
    poller.start();
    await vi.waitFor(() => expect(urls.length).toBeGreaterThanOrEqual(2));
    await poller.stop();
    expect(slept[0]).toBe(1000);
  });

  it("escalates the backoff while failures continue", async () => {
    const slept: number[] = [];
    const fn = (async () =>
      new Response(JSON.stringify({ ok: false, description: "nope" }), {
        status: 500,
      })) as unknown as typeof fetch;
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
      sleepFn: yieldingSleep(slept),
    });
    poller.start();
    await vi.waitFor(() => expect(slept.length).toBeGreaterThanOrEqual(3));
    await poller.stop();
    expect(slept[1]).toBe(2000);
    expect(slept[2]).toBe(4000);
  });

  // 409 means a webhook is registered, or a second poller is running. Neither fixes itself by
  // waiting, so the log has to say what to do.
  it("explains a 409 instead of retrying silently", async () => {
    const log = fakeLog();
    const fn = (async () =>
      new Response(
        JSON.stringify({
          ok: false,
          description: "Conflict: can't use getUpdates method while webhook is active",
        }),
        { status: 409 },
      )) as unknown as typeof fetch;
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log,
      onUpdate: async () => {},
      sleepFn: yieldingSleep(),
    });
    poller.start();
    await vi.waitFor(() => expect(log.lines.some((l) => l.startsWith("error"))).toBe(true));
    await poller.stop();
    const line = log.lines.find((l) => l.startsWith("error"))!;
    expect(line).toMatch(/webhook/i);
    expect(line).toMatch(/deleteWebhook/);
  });

  it("names a bad bot token rather than retrying quietly", async () => {
    const log = fakeLog();
    const fn = (async () =>
      new Response(JSON.stringify({ ok: false, description: "Unauthorized" }), {
        status: 401,
      })) as unknown as typeof fetch;
    const poller = new TelegramPoller({
      botToken: "bad",
      fetchFn: fn,
      log,
      onUpdate: async () => {},
      sleepFn: yieldingSleep(),
    });
    poller.start();
    await vi.waitFor(() => expect(log.lines.some((l) => l.startsWith("error"))).toBe(true));
    await poller.stop();
    expect(log.lines.find((l) => l.startsWith("error"))).toMatch(/DFIR_TELEGRAM_BOT_TOKEN/);
  });

  it("stop() is idempotent and safe before any round completes", async () => {
    const { fn } = fetchServing([]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
    });
    poller.start();
    await poller.stop();
    await expect(poller.stop()).resolves.toBeUndefined();
  });

  it("start() twice does not run two loops", async () => {
    const { fn, urls } = fetchServing([{ body: { ok: true, result: [] } }]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
    });
    poller.start();
    poller.start();
    await vi.waitFor(() => expect(urls.length).toBeGreaterThanOrEqual(1));
    await poller.stop();
    expect(urls.length).toBeLessThanOrEqual(2); // one in-flight round, not two loops racing
  });
});

describe("sendTelegramMessage", () => {
  it("posts to the Bot API with the chat id and text", async () => {
    const calls: Array<{ url: string; body: { chat_id: string; text: string } }> = [];
    const fn = (async (url: string, init: { body: string }) => {
      calls.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response("ok", { status: 200 });
    }) as unknown as typeof fetch;

    await sendTelegramMessage({ botToken: "T", chatId: "-100", text: "hello", fetchFn: fn, log: fakeLog() });
    expect(calls[0].url).toBe("https://api.telegram.org/botT/sendMessage");
    expect(calls[0].body).toEqual({ chat_id: "-100", text: "hello" });
  });

  it("logs rather than throws when delivery fails", async () => {
    const log = fakeLog();
    const fn = (async () => {
      throw new Error("network down");
    }) as unknown as typeof fetch;
    await expect(
      sendTelegramMessage({ botToken: "T", chatId: "-100", text: "x", fetchFn: fn, log }),
    ).resolves.toBeUndefined();
    expect(log.lines.some((l) => l.includes("network down"))).toBe(true);
  });

  it("honours an API base override", async () => {
    const urls: string[] = [];
    const fn = (async (url: string) => {
      urls.push(String(url));
      return new Response("ok", { status: 200 });
    }) as unknown as typeof fetch;
    await sendTelegramMessage({
      botToken: "T",
      chatId: "1",
      text: "x",
      apiBase: "http://localhost:9099/",
      fetchFn: fn,
      log: fakeLog(),
    });
    expect(urls[0]).toBe("http://localhost:9099/botT/sendMessage");
  });
});
