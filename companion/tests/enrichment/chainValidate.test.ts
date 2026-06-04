import { describe, it, expect } from "vitest";
import { validateProcessChains } from "../../src/enrichment/chainValidate.js";
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
});
