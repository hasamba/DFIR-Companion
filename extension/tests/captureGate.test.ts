import { describe, expect, it } from "vitest";
import {
  AUTO_CAPTURE_MIN_GAP_MS,
  CaptureGate,
  isAutomaticTrigger,
  isCaptureRateLimitError,
} from "../src/captureGate.js";

// A controllable clock and a sleep that advances it, so the gap logic runs without real timers.
function fakeClock(start = 1_000_000) {
  let t = start;
  const sleeps: number[] = [];
  return {
    now: () => t,
    advance: (ms: number) => { t += ms; },
    sleep: async (ms: number) => { sleeps.push(ms); t += ms; },
    sleeps,
  };
}

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

describe("isAutomaticTrigger", () => {
  it("treats timer, tab switch, navigation and click as automatic", () => {
    for (const t of ["timer", "tab_switch", "navigation", "click"] as const) {
      expect(isAutomaticTrigger(t, false)).toBe(true);
    }
  });

  it("treats manual and one-off captures as analyst-initiated", () => {
    expect(isAutomaticTrigger("manual", false)).toBe(false);
    expect(isAutomaticTrigger("click", true)).toBe(false);
  });
});

describe("isCaptureRateLimitError", () => {
  it("recognises Chrome's captureVisibleTab quota error", () => {
    const e = new Error(
      "This request exceeds the MAX_CAPTURE_VISIBLE_TAB_CALLS_PER_SECOND quota.",
    );
    expect(isCaptureRateLimitError(e)).toBe(true);
    expect(isCaptureRateLimitError({ message: e.message })).toBe(true);
  });

  it("does not mistake a real permission denial for a rate limit", () => {
    expect(isCaptureRateLimitError(new Error("Cannot access contents of the page"))).toBe(false);
    expect(isCaptureRateLimitError(undefined)).toBe(false);
    expect(isCaptureRateLimitError("boom")).toBe(false);
  });
});

describe("CaptureGate", () => {
  it("uses a gap that keeps two captures under Chrome's ~2 per second limit", () => {
    expect(AUTO_CAPTURE_MIN_GAP_MS).toBeGreaterThanOrEqual(500);
  });

  it("runs an automatic capture when idle", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    await expect(gate.run(true, async () => "ran", "skipped")).resolves.toBe("ran");
  });

  it("drops an automatic trigger while another capture is in flight", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    const first = deferred<string>();
    const a = gate.run(true, () => first.promise, "skipped");
    c.advance(5_000); // even long after the gap, in-flight still blocks
    let secondRan = false;
    const b = gate.run(true, async () => { secondRan = true; return "ran"; }, "skipped");
    await expect(b).resolves.toBe("skipped");
    first.resolve("first");
    await expect(a).resolves.toBe("first");
    expect(secondRan).toBe(false);
  });

  it("drops an automatic trigger inside the minimum gap (click + navigation from one link)", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    await gate.run(true, async () => "click", "skipped");
    c.advance(200);
    await expect(gate.run(true, async () => "nav", "skipped")).resolves.toBe("skipped");
  });

  it("allows the next automatic trigger once the gap has passed", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    await gate.run(true, async () => "one", "skipped");
    c.advance(600);
    await expect(gate.run(true, async () => "two", "skipped")).resolves.toBe("two");
  });

  it("drops two automatic triggers fired in the same tick", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    const results = await Promise.all([
      gate.run(true, async () => "a", "skipped"),
      gate.run(true, async () => "b", "skipped"),
    ]);
    expect(results).toEqual(["a", "skipped"]);
  });

  it("never drops a manual capture: it waits for the in-flight one and the gap", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    const first = deferred<string>();
    const order: string[] = [];
    const a = gate.run(true, async () => { const v = await first.promise; order.push(v); return v; }, "skipped");
    const m = gate.run(false, async () => { order.push("manual"); return "manual"; }, "skipped");
    await Promise.resolve();
    expect(order).toEqual([]);
    first.resolve("auto");
    await expect(a).resolves.toBe("auto");
    await expect(m).resolves.toBe("manual");
    expect(order).toEqual(["auto", "manual"]);
    expect(c.sleeps).toEqual([600]); // no time passed on the fake clock, so the full gap is waited
  });

  it("does not sleep for a manual capture when the gap already passed", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    await gate.run(true, async () => "auto", "skipped");
    c.advance(10_000);
    await gate.run(false, async () => "manual", "skipped");
    expect(c.sleeps).toEqual([]);
  });

  it("blocks automatic triggers while a manual capture waits its turn", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    const first = deferred<string>();
    const a = gate.run(false, () => first.promise, "skipped");
    await expect(gate.run(true, async () => "auto", "skipped")).resolves.toBe("skipped");
    first.resolve("manual");
    await a;
  });

  it("keeps working after a capture throws", async () => {
    const c = fakeClock();
    const gate = new CaptureGate(600, c.now, c.sleep);
    await expect(gate.run(true, async () => { throw new Error("x"); }, "skipped")).rejects.toThrow("x");
    c.advance(600);
    await expect(gate.run(true, async () => "ok", "skipped")).resolves.toBe("ok");
  });
});
