import { describe, expect, it } from "vitest";
import {
  MirrorRateLimiter,
  fetchBotUsername,
  mirrorBackoffMs,
  sendMirrorMessage,
} from "../../../src/integrations/telegram/watsonMirrorSender.js";

// #2647: the mirror's Bot API sender. Every outcome is classified so the service can tell "the chat
// is gone" (stop mirroring) from "Telegram is busy" (wait) from "this one message was refused" (hold).

function fakeFetch(status: number, body: unknown) {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  const fn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, body: JSON.parse(String(init?.body ?? "{}")) });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { fn, calls };
}

const send = (fetchFn: typeof fetch) =>
  sendMirrorMessage({ botToken: () => " 123:ABC ", chatId: "-100", text: "<b>x</b>", fetchFn });

describe("sendMirrorMessage", () => {
  it("sends HTML with link previews off and returns the message id", async () => {
    const f = fakeFetch(200, { ok: true, result: { message_id: 77 } });
    expect(await send(f.fn)).toEqual({ kind: "sent", messageId: 77 });
    expect(f.calls[0].url).toBe("https://api.telegram.org/bot123:ABC/sendMessage");
    expect(f.calls[0].body).toEqual({
      chat_id: "-100",
      text: "<b>x</b>",
      parse_mode: "HTML",
      link_preview_options: { is_disabled: true },
    });
  });

  it("reads retry_after from a 429", async () => {
    const f = fakeFetch(429, { ok: false, description: "Too Many Requests", parameters: { retry_after: 7 } });
    expect(await send(f.fn)).toEqual({ kind: "rate_limited", retryAfterMs: 7000 });
  });

  it("treats 403 and 'chat not found' as the chat being gone", async () => {
    expect(
      await send(fakeFetch(403, { ok: false, description: "Forbidden: bot was kicked" }).fn),
    ).toMatchObject({
      kind: "gone",
    });
    expect(
      await send(fakeFetch(400, { ok: false, description: "Bad Request: chat not found" }).fn),
    ).toMatchObject({
      kind: "gone",
    });
  });

  it("treats any other 400 as a refused message, never as a gone chat", async () => {
    const out = await send(
      fakeFetch(400, { ok: false, description: "Bad Request: can't parse entities" }).fn,
    );
    expect(out).toEqual({ kind: "rejected", reason: "Bad Request: can't parse entities" });
  });

  it("treats 5xx and network failures as transient", async () => {
    expect(await send(fakeFetch(502, { ok: false }).fn)).toMatchObject({ kind: "transient" });
    const boom = (async () => {
      throw new Error("ECONNRESET");
    }) as unknown as typeof fetch;
    expect(await send(boom)).toEqual({ kind: "transient", reason: "ECONNRESET" });
  });

  it("reports a missing token as transient without calling Telegram", async () => {
    const f = fakeFetch(200, {});
    expect(await sendMirrorMessage({ botToken: "", chatId: "1", text: "x", fetchFn: f.fn })).toMatchObject({
      kind: "transient",
    });
    expect(f.calls).toEqual([]);
  });
});

describe("mirrorBackoffMs", () => {
  it("follows 5 s, 30 s, 2 min, 10 min, then hourly", () => {
    expect([0, 1, 2, 3, 4, 9].map(mirrorBackoffMs)).toEqual([
      5_000, 30_000, 120_000, 600_000, 3_600_000, 3_600_000,
    ]);
  });
});

describe("MirrorRateLimiter", () => {
  it("allows one message a second per chat", () => {
    const l = new MirrorRateLimiter();
    expect(l.waitMs("1", false, 0)).toBe(0);
    l.record("1", false, 0);
    expect(l.waitMs("1", false, 400)).toBe(600);
    expect(l.waitMs("2", false, 400)).toBe(0);
    expect(l.waitMs("1", false, 1000)).toBe(0);
  });

  it("allows 20 messages a minute per group", () => {
    const l = new MirrorRateLimiter();
    for (let i = 0; i < 20; i++) l.record("-5", true, i * 1000);
    expect(l.waitMs("-5", true, 20_000)).toBe(40_000);
    expect(l.waitMs("-5", true, 60_000)).toBe(0);
  });
});

describe("fetchBotUsername", () => {
  it("reads the bot's username from getMe", async () => {
    const f = fakeFetch(200, { ok: true, result: { username: "DfirBot" } });
    expect(await fetchBotUsername({ botToken: "t", fetchFn: f.fn })).toBe("DfirBot");
    expect(f.calls[0].url).toBe("https://api.telegram.org/bott/getMe");
  });

  it("returns undefined when Telegram cannot say", async () => {
    expect(
      await fetchBotUsername({ botToken: "t", fetchFn: fakeFetch(401, { ok: false }).fn }),
    ).toBeUndefined();
  });
});
