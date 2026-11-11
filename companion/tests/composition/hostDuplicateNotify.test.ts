// #2584: the import-time "Analysis on hold" check reads every host name in the super-timeline. It
// ran after EVERY import, and every import changes the super-timeline, so its memo missed each time
// and a 3,872-file drop paid one whole-store scan per file (O(n²)), overlapping the next import.
// The notifier coalesces those kicks: one check per quiet period, a bounded wait for drops that
// never go quiet, never two checks of one case at once, and nothing for a deleted case.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { forgetCaseKeyedState } from "../../src/storage/caseKeyedState.js";
import { captureCaseScope, runInCaseScope } from "../../src/storage/caseIncarnation.js";
import {
  createHostDuplicateNotifier,
  HOST_DUPLICATE_NOTIFY_MAX_WAIT_MS,
  HOST_DUPLICATE_NOTIFY_QUIET_MS,
} from "../../src/composition/hostDuplicateNotify.js";
import type { NotificationEvent } from "../../src/analysis/notifications.js";

const QUIET = 2_000;
const MAX_WAIT = 60_000;

let root: string;
let cases: CaseStore;

function event(caseId: string): NotificationEvent {
  return { kind: "milestone", caseId, title: "hold", severity: "Info", lines: [], at: "t" };
}

function notifier(check: (caseId: string) => Promise<NotificationEvent | null>) {
  const deliver = vi.fn();
  const n = createHostDuplicateNotifier({
    casesRoot: () => root,
    check,
    deliver,
    quietMs: QUIET,
    maxWaitMs: MAX_WAIT,
  });
  // The production caller kicks from inside the case's scope (resynthesizeInBackground).
  const kick = (caseId: string) => runInCaseScope(root, caseId, () => n.kick(caseId));
  return { n, kick, deliver };
}

beforeEach(async () => {
  vi.useFakeTimers();
  root = await mkdtemp(join(tmpdir(), "dfir-hostdup-coalesce-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("host-duplicate notification coalescing (#2584)", () => {
  it("defaults to a 2 s quiet period and a 60 s maximum wait", () => {
    expect(HOST_DUPLICATE_NOTIFY_QUIET_MS).toBe(2_000);
    expect(HOST_DUPLICATE_NOTIFY_MAX_WAIT_MS).toBe(60_000);
  });

  it("a burst of imports costs one check, after the case goes quiet", async () => {
    const check = vi.fn(async (caseId: string) => event(caseId));
    const { kick, deliver } = notifier(check);
    for (let i = 0; i < 500; i++) {
      kick("c1");
      await vi.advanceTimersByTimeAsync(100); // a small-file drop: one import every 100 ms
    }
    expect(check).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(QUIET);
    expect(check).toHaveBeenCalledTimes(1);
    expect(deliver).toHaveBeenCalledTimes(1);
  });

  it("the check count does not grow with the import count", async () => {
    const counts: number[] = [];
    for (const imports of [10, 1_000]) {
      const check = vi.fn(async () => null);
      const { kick, n } = notifier(check);
      for (let i = 0; i < imports; i++) {
        kick("c1");
        await vi.advanceTimersByTimeAsync(20);
      }
      await vi.advanceTimersByTimeAsync(QUIET);
      counts.push(check.mock.calls.length);
      n.dispose();
    }
    expect(counts).toEqual([1, 1]);
  });

  it("a drop that never goes quiet is still checked within the maximum wait", async () => {
    const check = vi.fn(async () => null);
    const { kick } = notifier(check);
    for (let elapsed = 0; elapsed < 3 * MAX_WAIT; elapsed += 500) {
      kick("c1");
      await vi.advanceTimersByTimeAsync(500);
    }
    // One check per maximum wait, not one per kick (360 kicks).
    expect(check.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(check.mock.calls.length).toBeLessThanOrEqual(3);
  });

  it("never runs two checks of one case at once; a kick during a check earns one more run", async () => {
    let release: () => void = () => undefined;
    let running = 0;
    let maxRunning = 0;
    const check = vi.fn(async () => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise<void>((r) => (release = r));
      running--;
      return null;
    });
    const { kick } = notifier(check);
    kick("c1");
    await vi.advanceTimersByTimeAsync(QUIET);
    expect(check).toHaveBeenCalledTimes(1);
    // Imports keep landing while the (slow) check runs, then the case goes quiet.
    for (let i = 0; i < 10; i++) {
      kick("c1");
      await vi.advanceTimersByTimeAsync(QUIET * 2);
    }
    expect(check).toHaveBeenCalledTimes(1);
    release();
    await vi.advanceTimersByTimeAsync(QUIET);
    expect(check).toHaveBeenCalledTimes(2);
    release();
    await vi.advanceTimersByTimeAsync(QUIET * 5);
    expect(check).toHaveBeenCalledTimes(2);
    expect(maxRunning).toBe(1);
  });

  it("cases are independent", async () => {
    const check = vi.fn(async (caseId: string) => event(caseId));
    const { kick, deliver } = notifier(check);
    kick("c1");
    await vi.advanceTimersByTimeAsync(QUIET / 2);
    kick("c2");
    await vi.advanceTimersByTimeAsync(QUIET / 2);
    expect(check.mock.calls.map((c) => c[0])).toEqual(["c1"]);
    await vi.advanceTimersByTimeAsync(QUIET);
    expect(check.mock.calls.map((c) => c[0])).toEqual(["c1", "c2"]);
    expect(deliver).toHaveBeenCalledTimes(2);
  });

  it("a failed check does not wedge the case", async () => {
    const check = vi.fn().mockRejectedValueOnce(new Error("store gone")).mockResolvedValue(event("c1"));
    const { kick, deliver } = notifier(check);
    kick("c1");
    await vi.advanceTimersByTimeAsync(QUIET);
    kick("c1");
    await vi.advanceTimersByTimeAsync(QUIET);
    expect(check).toHaveBeenCalledTimes(2);
    expect(deliver).toHaveBeenCalledTimes(1);
  });

  it("a deleted case's pending check never runs", async () => {
    const check = vi.fn(async (caseId: string) => event(caseId));
    const { kick, deliver } = notifier(check);
    kick("c1");
    forgetCaseKeyedState(root, "c1");
    await vi.advanceTimersByTimeAsync(QUIET * 2);
    expect(check).not.toHaveBeenCalled();
    expect(deliver).not.toHaveBeenCalled();
  });

  it("a case deleted while its check runs gets no notification", async () => {
    let release: () => void = () => undefined;
    const check = vi.fn(async (caseId: string) => {
      await new Promise<void>((r) => (release = r));
      return event(caseId);
    });
    const { kick, deliver } = notifier(check);
    kick("c1");
    await vi.advanceTimersByTimeAsync(QUIET);
    expect(check).toHaveBeenCalledTimes(1);
    forgetCaseKeyedState(root, "c1");
    release();
    await vi.advanceTimersByTimeAsync(QUIET);
    expect(deliver).not.toHaveBeenCalled();
  });

  it("old work of a deleted case cannot kick a check for its same-id successor", async () => {
    const check = vi.fn(async (caseId: string) => event(caseId));
    const { n, deliver } = notifier(check);
    const old = captureCaseScope(root, "c1"); // an import of the first incarnation, still finishing
    await cases.deleteCaseFolder("c1");
    forgetCaseKeyedState(root, "c1");
    await cases.createCase({ caseId: "c1", name: "again", investigator: "i", aiProvider: null });
    old(() => n.kick("c1"));
    await vi.advanceTimersByTimeAsync(QUIET * 2);
    expect(check).not.toHaveBeenCalled();
    expect(deliver).not.toHaveBeenCalled();
  });

  it("after dispose nothing pending runs, nothing running is delivered, and kicks are ignored", async () => {
    let release: () => void = () => undefined;
    const check = vi.fn(async (caseId: string) => {
      if (caseId === "c1") await new Promise<void>((r) => (release = r));
      return event(caseId);
    });
    const { kick, n, deliver } = notifier(check);
    kick("c1");
    await vi.advanceTimersByTimeAsync(QUIET); // c1 running
    kick("c2"); // c2 pending
    n.dispose();
    release();
    kick("c2");
    await vi.advanceTimersByTimeAsync(QUIET * 3);
    expect(check.mock.calls.map((c) => c[0])).toEqual(["c1"]);
    expect(deliver).not.toHaveBeenCalled();
  });

  it("its timers never keep the process alive", () => {
    const spy = vi.spyOn(globalThis, "setTimeout");
    const { kick } = notifier(async () => null);
    kick("c1");
    const handle = spy.mock.results.at(-1)?.value as { hasRef?: () => boolean };
    expect(handle.hasRef?.()).toBe(false);
    spy.mockRestore();
  });
});
