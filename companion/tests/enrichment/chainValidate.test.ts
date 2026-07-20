import { describe, it, expect } from "vitest";
import { validateProcessChains, hasChainWork } from "../../src/enrichment/chainValidate.js";
import { RateLimitError } from "../../src/enrichment/provider.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { ParentChildResult } from "../../src/enrichment/rockyraccoon.js";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return { id: over.id, timestamp: "t", description: "d", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over };
}
const noSleep = async () => {};
const now = () => "2026-06-04T00:00:00Z";

describe("validateProcessChains", () => {
  it("flags an unobserved parent→child as a chainCheck anomaly", async () => {
    const calls: string[] = [];
    const check = async (p: string, c: string): Promise<ParentChildResult> => {
      calls.push(`${p}>${c}`);
      return p === "excel.exe"
        ? { observed: false, note: "excel.exe → powershell.exe NOT observed" }
        : { observed: true, percentage: 98.7, note: "ok" };
    };
    const events = [
      ev({ id: "e1", parentName: "excel.exe", processName: "powershell.exe" }),
      ev({ id: "e2", parentName: "services.exe", processName: "svchost.exe" }),
      ev({ id: "e3", description: "no process here" }),  // not a candidate
    ];
    const { events: out, summary } = await validateProcessChains(events, { check, sleep: noSleep, now });
    expect(summary).toMatchObject({ candidates: 2, pairs: 2, checked: 2, anomalies: 1 });
    expect(out[0].chainCheck).toMatchObject({ observed: false });
    expect(out[1].chainCheck).toMatchObject({ observed: true });
    expect(out[2].chainCheck).toBeUndefined();
  });

  it("deduplicates by (parent,child) — one check applies to every event with that chain", async () => {
    let n = 0;
    const check = async (): Promise<ParentChildResult> => { n += 1; return { observed: false, note: "x" }; };
    const events = [
      ev({ id: "a", parentName: "excel.exe", processName: "powershell.exe" }),
      ev({ id: "b", parentName: "excel.exe", processName: "powershell.exe" }),
      ev({ id: "c", parentName: "EXCEL.EXE", processName: "PowerShell.exe" }), // same chain, different case
    ];
    const { events: out, summary } = await validateProcessChains(events, { check, sleep: noSleep, now });
    expect(n).toBe(1);                  // queried once
    expect(summary.pairs).toBe(1);
    expect(out.every((e) => e.chainCheck?.observed === false)).toBe(true);
  });

  it("skips already-checked events unless force, and honours maxChecks", async () => {
    const check = async (): Promise<ParentChildResult> => ({ observed: true, note: "ok" });
    const cached = ev({ id: "a", parentName: "p.exe", processName: "c.exe", chainCheck: { observed: true, note: "old", checkedAt: "old" } });
    const r1 = await validateProcessChains([cached], { check, sleep: noSleep, now });
    expect(r1.summary.checked).toBe(0); // cached → skipped
    const r2 = await validateProcessChains([cached], { check, sleep: noSleep, now, force: true });
    expect(r2.summary.checked).toBe(1);

    const many = [ev({ id: "1", parentName: "a", processName: "x" }), ev({ id: "2", parentName: "b", processName: "y" })];
    const capped = await validateProcessChains(many, { check, sleep: noSleep, now, maxChecks: 1 });
    expect(capped.summary.checked).toBe(1);
  });

  it("applies ± jitterMs on top of delayMs between checks", async () => {
    const slept: number[] = [];
    const check = async (): Promise<ParentChildResult> => ({ observed: true, note: "ok" });
    const events = [
      ev({ id: "a", parentName: "p1.exe", processName: "c1.exe" }),
      ev({ id: "b", parentName: "p2.exe", processName: "c2.exe" }),
    ];
    await validateProcessChains(events, {
      check, now, sleep: async (ms) => { slept.push(ms); }, delayMs: 1000, jitterMs: 200, random: () => 1,
    });
    expect(slept).toEqual([1200]);   // random()=1 → +jitterMs edge
  });

  it("retries a check() that throws RateLimitError instead of counting it as an immediate error", async () => {
    let attempts = 0;
    const check = async (): Promise<ParentChildResult> => {
      attempts++;
      if (attempts < 3) throw new RateLimitError("rate limited");
      return { observed: true, note: "ok" };
    };
    const events = [ev({ id: "a", parentName: "p.exe", processName: "c.exe" })];
    const { summary } = await validateProcessChains(events, { check, now, sleep: noSleep, retry: { retries: 3, backoffMs: 1 } });
    expect(attempts).toBe(3);
    expect(summary.checked).toBe(1);
    expect(summary.errors).toBe(0);
  });
});

describe("hasChainWork", () => {
  it("is false when every parent→child event already carries a chainCheck", () => {
    const events = [ev({ id: "a", parentName: "p.exe", processName: "c.exe", chainCheck: { observed: true, note: "ok", checkedAt: "t" } })];
    expect(hasChainWork(events)).toBe(false);
  });

  it("is true when at least one parent→child event has never been checked", () => {
    const events = [
      ev({ id: "a", parentName: "p.exe", processName: "c.exe", chainCheck: { observed: true, note: "ok", checkedAt: "t" } }),
      ev({ id: "b", parentName: "excel.exe", processName: "powershell.exe" }),
    ];
    expect(hasChainWork(events)).toBe(true);
  });

  it("is false for events with no parent/process pair", () => {
    expect(hasChainWork([ev({ id: "a", description: "no process here" })])).toBe(false);
  });

  it("is false for an empty timeline", () => {
    expect(hasChainWork([])).toBe(false);
  });
});
