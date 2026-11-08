import { describe, it, expect, vi } from "vitest";
import { TelegramPoller, type TelegramUpdate } from "../../src/analysis/telegramPoller.js";
import type { Logger } from "../../src/logging/logger.js";

// Issue #2411: stop() is prompt even mid-backoff, start() after stop() polls again, handled commands
// are confirmed on shutdown so a fresh process does not run them twice, and a cursor never crosses
// from one bot token to another.

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

const message = (id: number): TelegramUpdate => ({
  update_id: id,
  message: { chat: { id: -100 }, from: { id: 7 }, text: `/dfir status ${id}` },
});

type Round = { status?: number; body: unknown };

/** Serves queued long-poll rounds, then parks until aborted. Confirmation calls (timeout=0) are
 *  recorded separately and answered by `confirmReply`. */
function telegram(
  rounds: Round[],
  confirmReply: () => Response = () => Response.json({ ok: true, result: [] }),
) {
  const polls: string[] = [];
  const confirms: string[] = [];
  const fn = async (url: string, init?: { signal?: AbortSignal }) => {
    const u = String(url);
    if (u.includes("timeout=0")) {
      confirms.push(u);
      return confirmReply();
    }
    polls.push(u);
    const next = rounds.shift();
    if (!next) {
      await new Promise((_r, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    }
    return new Response(JSON.stringify(next!.body), { status: next!.status ?? 200 });
  };
  return { fn: fn as unknown as typeof fetch, polls, confirms };
}

const race = (p: Promise<unknown>) =>
  Promise.race([p.then(() => "stopped"), new Promise((r) => setTimeout(() => r("hung"), 1000))]);

describe("TelegramPoller lifecycle (#2411)", () => {
  it("stop() interrupts a long backoff sleep", async () => {
    const { fn } = telegram([{ status: 502, body: { ok: false, description: "Bad Gateway" } }]);
    const slept: number[] = [];
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
      sleepFn: (ms) => {
        slept.push(ms);
        return new Promise(() => {}); // never wakes on its own
      },
    });
    poller.start();
    await vi.waitFor(() => expect(slept).toHaveLength(1));
    await expect(race(poller.stop())).resolves.toBe("stopped");
  });

  it("start() after stop() polls again, from the same cursor", async () => {
    const { fn, polls } = telegram([{ body: { ok: true, result: [message(4)] } }]);
    const seen: number[] = [];
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async (u) => {
        seen.push(u.update_id);
      },
    });
    poller.start();
    await vi.waitFor(() => expect(polls).toHaveLength(2));
    await poller.stop();
    poller.start();
    await vi.waitFor(() => expect(polls).toHaveLength(3));
    await poller.stop();
    expect(polls[2]).toContain("offset=5");
    expect(seen).toEqual([4]);
  });

  it("confirms handled commands on shutdown so a fresh process does not replay them", async () => {
    const gate: { release?: () => void } = {};
    const { fn, confirms } = telegram([{ body: { ok: true, result: [message(20), message(21)] } }]);
    const seen: number[] = [];
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async (u) => {
        seen.push(u.update_id);
        if (u.update_id === 20) await new Promise<void>((r) => (gate.release = r));
      },
    });
    poller.start();
    await vi.waitFor(() => expect(gate.release).toBeDefined());
    const stopping = poller.stop(); // stop while the first command of the batch is still running
    gate.release!();
    await stopping;
    expect(seen).toEqual([20]); // 21 was never handled, so it is not confirmed
    expect(confirms).toHaveLength(1);
    expect(confirms[0]).toContain("offset=21");
    expect(confirms[0]).toContain("/botT/");
  });

  it("does not send a confirmation when the last poll already confirmed everything", async () => {
    const { fn, confirms, polls } = telegram([
      { body: { ok: true, result: [message(30)] } },
      { body: { ok: true, result: [] } },
    ]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
    });
    poller.start();
    await vi.waitFor(() => expect(polls).toHaveLength(3));
    await poller.stop();
    expect(confirms).toEqual([]);
  });

  it("logs, rather than throws, when the shutdown confirmation fails", async () => {
    const log = fakeLog();
    const { fn, polls } = telegram([{ body: { ok: true, result: [message(40)] } }], () => {
      throw new Error("network down");
    });
    const poller = new TelegramPoller({ botToken: "T", fetchFn: fn, log, onUpdate: async () => {} });
    poller.start();
    await vi.waitFor(() => expect(polls).toHaveLength(2));
    await expect(poller.stop()).resolves.toBeUndefined();
    expect(log.lines.some((l) => l.startsWith("warn") && l.includes("may run again"))).toBe(true);
  });

  it("drops the cursor when the bot token changes, never sending one bot's cursor to another", async () => {
    let token = "A";
    const { fn, polls, confirms } = telegram([
      { body: { ok: true, result: [message(50)] } },
      { body: { ok: true, result: [] } },
    ]);
    const handled: number[] = [];
    const poller = new TelegramPoller({
      botToken: () => token,
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async (u) => {
        handled.push(u.update_id);
        token = "B"; // rotated while the command ran
      },
    });
    poller.start();
    await vi.waitFor(() => expect(polls.length).toBeGreaterThanOrEqual(3));
    await poller.stop();
    expect(polls[1]).toContain("/botB/");
    expect(polls[1]).not.toContain("offset="); // bot A's cursor is not sent to bot B
    expect(confirms).toEqual([]); // bot B has no handled cursor; bot A's is never sent to B
    expect(handled).toEqual([50]);
  });

  it("concurrent stop() calls share one shutdown and one confirmation", async () => {
    const { fn, polls, confirms } = telegram([{ body: { ok: true, result: [message(60)] } }]);
    const poller = new TelegramPoller({
      botToken: "T",
      fetchFn: fn,
      log: fakeLog(),
      onUpdate: async () => {},
    });
    poller.start();
    await vi.waitFor(() => expect(polls).toHaveLength(2));
    await Promise.all([poller.stop(), poller.stop()]);
    expect(confirms).toHaveLength(1);
  });
});
