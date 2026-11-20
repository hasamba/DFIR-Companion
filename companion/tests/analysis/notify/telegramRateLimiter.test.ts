import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  TelegramBotLimiter,
  TelegramLimiters,
  TelegramRateLimitError,
  acquireAndCommit,
  isGroupChatId,
  sendWithTelegramLimit,
  telegramRetryAfterMs,
  type TelegramLane,
} from "../../../src/analysis/notify/telegramRateLimiter.js";

// #2711: one limiter per bot for alerts, command replies and the Watson mirror. Real limiter code on
// vitest's fake timers (Date.now + setTimeout), so concurrent waiters interleave the way they do live.

const T0 = Date.parse("2026-11-20T10:00:00.000Z");

beforeEach(() => {
  vi.useFakeTimers({ now: T0 });
});
afterEach(() => {
  vi.useRealTimers();
});

/** Start a send that commits as soon as it is granted; records the order and time of each grant. */
function sender(limiter: TelegramBotLimiter, log: string[], times: number[] = []) {
  return (label: string, chatId: string, lane: TelegramLane, isGroup?: boolean) =>
    acquireAndCommit(limiter, { chatId, lane, ...(isGroup === undefined ? {} : { isGroup }) }).then(() => {
      log.push(label);
      times.push(Date.now() - T0);
    });
}

describe("TelegramBotLimiter limits", () => {
  it("spaces sends to one chat a second apart, across lanes", async () => {
    const l = new TelegramBotLimiter();
    const log: string[] = [];
    const times: number[] = [];
    const send = sender(l, log, times);
    void send("m1", "100", "mirror");
    void send("a1", "100", "alert");
    void send("r1", "100", "reply");
    await vi.advanceTimersByTimeAsync(3_000);
    expect(times).toEqual([0, 1_000, 2_000]);
  });

  it("does not hold other chats back for one chat's spacing", async () => {
    const l = new TelegramBotLimiter();
    const log: string[] = [];
    const times: number[] = [];
    const send = sender(l, log, times);
    void send("m1", "100", "mirror");
    void send("m2", "100", "mirror");
    void send("m3", "200", "mirror");
    await vi.advanceTimersByTimeAsync(1_500);
    expect(log).toEqual(["m1", "m3", "m2"]);
    expect(times).toEqual([0, 0, 1_000]);
  });

  it("caps a group at 15 mirror sends a minute but lets an alert use the rest of its 20", async () => {
    const l = new TelegramBotLimiter();
    const log: string[] = [];
    const times: number[] = [];
    const send = sender(l, log, times);
    for (let i = 0; i < 16; i++) void send(`m${i}`, "-100", "mirror");
    await vi.advanceTimersByTimeAsync(15_500);
    expect(log).toHaveLength(15); // the 16th waits for the minute to roll over
    void send("alert", "-100", "alert");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(log.at(-1)).toBe("alert");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(log).toContain("m15");
    expect(times[log.indexOf("m15")]).toBeGreaterThanOrEqual(60_000);
  });

  it("counts every lane against one overall budget: the mirror stops at 20 a second, an alert still goes", async () => {
    const l = new TelegramBotLimiter();
    const log: string[] = [];
    const times: number[] = [];
    const send = sender(l, log, times);
    for (let i = 0; i < 22; i++) void send(`r${i}`, String(1000 + i), "reply");
    for (let i = 0; i < 3; i++) void send(`m${i}`, String(2000 + i), "mirror");
    await vi.advanceTimersByTimeAsync(0);
    // 22 replies went (reply cap 23); the mirror is already over its 20 of the shared history.
    expect(log.filter((x) => x.startsWith("r"))).toHaveLength(22);
    expect(log.filter((x) => x.startsWith("m"))).toHaveLength(0);
    void send("alert", "3000", "alert");
    await vi.advanceTimersByTimeAsync(0);
    expect(log.at(-1)).toBe("alert");
    await vi.advanceTimersByTimeAsync(1_100);
    expect(log.filter((x) => x.startsWith("m"))).toHaveLength(3);
  });
});

describe("TelegramBotLimiter priority — alerts are never delayed behind the mirror's backlog", () => {
  it("an alert to a busy mirror chat is the very next send to it", async () => {
    const l = new TelegramBotLimiter();
    const log: string[] = [];
    const times: number[] = [];
    const send = sender(l, log, times);
    for (let i = 0; i < 10; i++) void send(`m${i}`, "-100", "mirror");
    await vi.advanceTimersByTimeAsync(2_500); // m0 m1 m2 are out; seven still queued
    void send("alert", "-100", "alert");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(log.slice(0, 4)).toEqual(["m0", "m1", "m2", "alert"]);
    expect(times[3]).toBe(3_000); // just the 1 s spacing after m2, not after seven more
  });

  it("an alert's wait does not grow with the length of the mirror backlog", async () => {
    for (const backlog of [1, 50]) {
      const l = new TelegramBotLimiter();
      const log: string[] = [];
      const times: number[] = [];
      const send = sender(l, log, times);
      for (let i = 0; i < backlog; i++) void send(`m${i}`, String(5000 + (i % 25)), "mirror");
      void send("alert", "5000", "alert");
      const start = Date.now() - T0;
      await vi.advanceTimersByTimeAsync(1_000);
      expect(log).toContain("alert");
      expect(times[log.indexOf("alert")] - start).toBeLessThanOrEqual(1_000);
    }
  });

  it("a reply goes before a waiting mirror send, after a waiting alert", async () => {
    const l = new TelegramBotLimiter();
    const log: string[] = [];
    const send = sender(l, log);
    void send("first", "100", "mirror");
    void send("m", "100", "mirror");
    void send("r", "100", "reply");
    void send("a", "100", "alert");
    await vi.advanceTimersByTimeAsync(4_000);
    expect(log).toEqual(["first", "a", "r", "m"]);
  });
});

describe("TelegramBotLimiter reservations", () => {
  it("a slot taken while the holder re-checked something is refused at commit", async () => {
    const l = new TelegramBotLimiter();
    const slot = await l.acquire({ chatId: "100", lane: "mirror" });
    // The mirror is checking its authorization. An alert to the same chat waits its 1 s spacing
    // (the held reservation counts as a send), then goes while the mirror is still checking.
    const alert = acquireAndCommit(l, { chatId: "100", lane: "alert" });
    await vi.advanceTimersByTimeAsync(1_000);
    await alert;
    await vi.advanceTimersByTimeAsync(200);
    expect(slot.commit()).toBe(false); // 200 ms after the alert: too close, queue again
  });

  it("commit re-checks: a send recorded during the gap makes it fail, and the caller queues again", async () => {
    const l = new TelegramBotLimiter();
    const slot = await l.acquire({ chatId: "100", lane: "mirror" });
    l.backOff(2_000); // a 429 landed while the mirror re-checked
    expect(slot.commit()).toBe(false);
    const again = acquireAndCommit(l, { chatId: "100", lane: "mirror" });
    let done = false;
    void again.then(() => (done = true));
    await vi.advanceTimersByTimeAsync(1_900);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(200);
    expect(done).toBe(true);
  });

  it("a released reservation frees the chat at once", async () => {
    const l = new TelegramBotLimiter();
    const slot = await l.acquire({ chatId: "100", lane: "mirror" });
    slot.release();
    const next = await l.acquire({ chatId: "100", lane: "mirror" });
    expect(next.commit()).toBe(true);
  });
});

describe("TelegramBotLimiter 429 pause", () => {
  it("pauses every chat and lane until retry_after, and never shortens a longer pause", async () => {
    const l = new TelegramBotLimiter();
    l.backOff(5_000);
    l.backOff(1_000);
    const log: string[] = [];
    const times: number[] = [];
    const send = sender(l, log, times);
    void send("a", "100", "alert");
    void send("m", "200", "mirror");
    await vi.advanceTimersByTimeAsync(6_000);
    expect(times).toEqual([5_000, 5_000]);
  });

  it("gives up with TelegramRateLimitError past maxWaitMs and leaves the queue clean", async () => {
    const l = new TelegramBotLimiter();
    l.backOff(30_000);
    await expect(l.acquire({ chatId: "100", lane: "alert", maxWaitMs: 5_000 })).rejects.toBeInstanceOf(
      TelegramRateLimitError,
    );
    // The timed-out alert must not keep holding chat 100 against the mirror.
    await vi.advanceTimersByTimeAsync(30_000);
    const slot = await l.acquire({ chatId: "100", lane: "mirror" });
    expect(slot.commit()).toBe(true);
  });
});

describe("sendWithTelegramLimit", () => {
  it("pauses the bot on a 429 and retries once after retry_after", async () => {
    const l = new TelegramBotLimiter();
    const statuses = [429, 200];
    const at: number[] = [];
    const p = sendWithTelegramLimit(
      l,
      { chatId: "100", lane: "alert" },
      async () => {
        at.push(Date.now() - T0);
        return statuses.shift()!;
      },
      (s) => (s === 429 ? 3_000 : undefined),
      { maxRetryWaitMs: 60_000 },
    );
    await vi.advanceTimersByTimeAsync(3_100);
    expect(await p).toBe(200);
    expect(at).toEqual([0, 3_000]);
  });

  it("does not retry a second 429, nor a 429 that asks for longer than the cap", async () => {
    const l = new TelegramBotLimiter();
    let calls = 0;
    const p = sendWithTelegramLimit(
      l,
      { chatId: "100", lane: "reply" },
      async () => (++calls, 429),
      () => 1_000,
      { maxRetryWaitMs: 60_000 },
    );
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await p).toBe(429);
    expect(calls).toBe(2);

    const l2 = new TelegramBotLimiter();
    let calls2 = 0;
    const q = sendWithTelegramLimit(
      l2,
      { chatId: "100", lane: "alert" },
      async () => (++calls2, 429),
      () => 90_000,
      { maxRetryWaitMs: 60_000 },
    );
    expect(await q).toBe(429);
    expect(calls2).toBe(1);
  });

  it("sends straight away with no limiter", async () => {
    expect(
      await sendWithTelegramLimit(
        undefined,
        { chatId: "1", lane: "alert" },
        async () => 7,
        () => 1,
        { maxRetryWaitMs: 0 },
      ),
    ).toBe(7);
  });
});

describe("TelegramLimiters", () => {
  it("keeps one limiter per bot id, so a rotated token for the same bot shares its history", () => {
    const r = new TelegramLimiters();
    expect(r.forToken("123:OLD")).toBe(r.forToken("123:NEW"));
    expect(r.forToken("123:OLD")).not.toBe(r.forToken("456:OTHER"));
    expect(() => r.forToken("")).not.toThrow();
    expect(r.forToken(undefined)).toBe(r.forToken("  "));
  });
});

describe("helpers", () => {
  it("reads retry_after from a 429 body, text or parsed", () => {
    expect(telegramRetryAfterMs(429, '{"ok":false,"parameters":{"retry_after":7}}')).toBe(7_000);
    expect(telegramRetryAfterMs(429, { parameters: { retry_after: 2 } })).toBe(2_000);
    expect(telegramRetryAfterMs(429, "not json")).toBe(5_000);
    expect(telegramRetryAfterMs(200, '{"parameters":{"retry_after":7}}')).toBeUndefined();
  });

  it("treats negative ids and @names as groups, positive ids as private chats", () => {
    expect(isGroupChatId("-1001234")).toBe(true);
    expect(isGroupChatId("@channel")).toBe(true);
    expect(isGroupChatId("42")).toBe(false);
  });
});
