import { describe, expect, it } from "vitest";
import { emptyState, type ForensicEvent } from "../../../src/analysis/stateTypes.js";
import { watsonTimelineBlock } from "../../../src/analysis/ai/watson/watsonTimeline.js";

// #2656: when Watson's case view cannot carry every in-scope event, it keeps the most significant
// ones (synthesis's own seat selection), not the earliest, and still lists them in time order.

const word = (i: number): string => i.toString(36).replace(/\d/g, (d) => "qwrtyuiopz"[Number(d)]);
const ev = (id: string, over: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T10:00:00Z",
  description: `event ${id}`,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});
/** Distinct patterns (no burst grouping), one minute apart, early in the day. */
const early = (n: number, pad = 40): ForensicEvent[] =>
  Array.from({ length: n }, (_, i) =>
    ev(`m${i}`, {
      timestamp: new Date(Date.UTC(2026, 0, 1, 1, i)).toISOString(),
      description: `tool ${word(i)} ran ${word(i * 7 + 3)} ${"x".repeat(pad)}`,
    }),
  );
const block = (events: ForensicEvent[], budget: number) =>
  watsonTimelineBlock({ ...emptyState("c1"), forensicTimeline: events }, events, budget);
const idsIn = (text: string): string[] => [...text.matchAll(/^\[([^\]]+)\]/gm)].map((m) => m[1]);

describe("Watson's timeline block keeps the most significant events (#2656)", () => {
  it("a late Critical event past what the earliest rows would fill is shown", () => {
    const late = ev("crit", {
      severity: "Critical",
      timestamp: "2026-01-01T23:00:00Z",
      description: "ntds.dit copied by vssadmin",
    });
    const events = [...early(300), late];
    const out = block(events, 6000);
    expect(out.text.length).toBeLessThanOrEqual(6000);
    expect(idsIn(out.text)).toContain("crit");
    expect(out.used).toBeLessThan(events.length);
  });

  it("lists the rows it keeps in time order", () => {
    const events = [...early(300), ev("crit", { severity: "Critical", timestamp: "2026-01-01T23:00:00Z" })];
    const ids = idsIn(block(events, 6000).text);
    const at = new Map(events.map((e) => [e.id, e.timestamp]));
    const times = ids.map((id) => at.get(id)!);
    expect(times).toEqual([...times].sort());
  });

  it("more Critical/High rows than fit: the block still fits and says how many it shows", () => {
    const highs = early(200).map((e) => ({ ...e, severity: "High" as const }));
    const out = block(highs, 5000);
    expect(out.text.length).toBeLessThanOrEqual(5000);
    expect(out.used).toBe(idsIn(out.text).length);
    expect(out.text).toContain(`(showing ${out.used} of 200 in-scope events`);
  });

  it("everything fits: every event, no partial note", () => {
    const events = early(5);
    const out = block(events, 60000);
    expect(out.used).toBe(5);
    expect(out.text).not.toContain("ask for a 'lookup'");
  });

  it("one long early row does not empty the block when a short Critical row fits", () => {
    const huge = ev("huge", { timestamp: "2026-01-01T00:00:00Z", description: "y".repeat(5000) });
    const crit = ev("crit", {
      severity: "Critical",
      timestamp: "2026-01-01T23:00:00Z",
      description: "short",
    });
    // Descriptions are capped for the prompt; a budget under one capped row still forces the choice.
    const out = block([huge, crit], 500);
    expect(out.text.length).toBeLessThanOrEqual(500);
    expect(idsIn(out.text)).toEqual(["crit"]);
  });

  it("a single row longer than the budget is clipped, never dropped or overflowing", () => {
    const only = ev("only", { severity: "Critical", description: "z".repeat(5000) });
    const out = block([only], 500);
    expect(out.text.length).toBeLessThanOrEqual(500);
    expect(idsIn(out.text)).toEqual(["only"]);
  });

  it("an empty case and an Info-only case show no rows", () => {
    expect(block([], 2000).text).toContain("(no events shown)");
    const info = block([ev("i1", { severity: "Info" })], 2000);
    expect(info.text).toContain("(no events shown)");
    expect(info.used).toBe(0);
  });

  it("a burst of the same detection is one grouped row that covers its members", () => {
    const burst = Array.from({ length: 30 }, (_, i) =>
      ev(`b${i}`, {
        timestamp: new Date(Date.UTC(2026, 0, 1, 2, i)).toISOString(),
        description: `Velociraptor [Windows.Detection.Sigma] Sigma: Encoded PowerShell Command Line - Computer: ws-${i}`,
        severity: "High",
      }),
    );
    const out = block(burst, 60000);
    expect(idsIn(out.text)).toHaveLength(1);
    expect(out.text).toContain("grouped: 30×");
    expect(out.used).toBe(30);
  });
});
