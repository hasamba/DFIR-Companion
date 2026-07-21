import { describe, it, expect } from "vitest";
import { selectSynthesisEvents, selectSynthesisEventsAnnotated, buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";

function ev(id: string, t: string, sev: Severity): ForensicEvent {
  return { id, timestamp: t, description: id, severity: sev, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] };
}

function host(e: ForensicEvent, asset: string, processName?: string): ForensicEvent {
  return { ...e, asset, processName };
}

describe("selectSynthesisEvents", () => {
  it("returns everything (chronological) when under the budget", () => {
    const events = [ev("b", "2026-05-20T11:00:00Z", "Low"), ev("a", "2026-05-20T09:00:00Z", "Low")];
    expect(selectSynthesisEvents(events, 300).map((e) => e.id)).toEqual(["a", "b"]);
  });

  it("keeps all Critical/High, the earliest events, and a time-spread sample — chronologically", () => {
    const events: ForensicEvent[] = [];
    // 100 Low events across a day, plus two High/Critical buried in the middle, plus an early Low.
    for (let i = 0; i < 100; i++) {
      const hh = String(i % 24).padStart(2, "0");
      events.push(ev(`low${i}`, `2026-05-20T${hh}:00:00Z`, "Low"));
    }
    events.push(ev("crit", "2026-05-20T12:30:00Z", "Critical"));
    events.push(ev("high", "2026-05-20T13:30:00Z", "High"));

    const picked = selectSynthesisEvents(events, 30);
    const ids = picked.map((e) => e.id);
    expect(picked.length).toBeLessThanOrEqual(30);
    expect(ids).toContain("crit");                 // all Critical/High kept
    expect(ids).toContain("high");
    expect(ids).toContain("low0");                 // earliest (initial-access) kept
    // chronological order
    const times = picked.map((e) => e.timestamp);
    expect(times).toEqual([...times].sort());
  });

  it("builds no candidate list for a reserved class it has no budget to fill", () => {
    // 20 Critical anchors exactly fill a budget of 20, so every reserved class afterwards arrives with
    // nothing to give. Each class's candidates cost at least a full pass over the timeline, so assembling
    // one here is pure waste — and `rarityOf` is the one builder a caller can observe, which makes it the
    // probe: any call to it means a list was built and thrown away.
    const events: ForensicEvent[] = [];
    for (let i = 0; i < 20; i++) events.push(ev(`crit${i}`, `2026-05-20T${String(i).padStart(2, "0")}:00:00Z`, "Critical"));
    for (let i = 0; i < 30; i++) events.push(ev(`low${i}`, `2026-05-21T${String(i % 24).padStart(2, "0")}:00:00Z`, "Low"));

    let rarityCalls = 0;
    const picked = selectSynthesisEvents(events, 20, (e) => { rarityCalls++; return e.id.startsWith("low") ? 1 : 0; });

    expect(picked.length).toBe(20);
    expect(picked.every((e) => e.severity === "Critical")).toBe(true);   // budget went entirely to anchors
    expect(rarityCalls).toBe(0);
  });

  it("keeps the severest when Critical/High alone exceed the budget", () => {
    const events = Array.from({ length: 50 }, (_, i) => ev(`c${i}`, `2026-05-20T${String(i % 24).padStart(2, "0")}:00:00Z`, "Critical"));
    expect(selectSynthesisEvents(events, 10).length).toBe(10);
  });

  it("still includes the earliest events when Critical/High alone exceed the budget", () => {
    // 50 Criticals spread across a day; the earliest is at 00:00 and must survive the overflow trim.
    const events = Array.from({ length: 50 }, (_, i) =>
      ev(`c${i}`, `2026-05-20T${String(i % 24).padStart(2, "0")}:00:00Z`, "Critical"),
    );
    // A Low event BEFORE all of them — the initial-access context the old branch threw away.
    events.push(ev("firstContact", "2026-05-19T23:00:00Z", "Low"));

    const picked = selectSynthesisEvents(events, 10);
    expect(picked.length).toBe(10);
    expect(picked.map((e) => e.id)).toContain("firstContact");
    const times = picked.map((e) => e.timestamp);
    expect(times).toEqual([...times].sort());
  });

  it("drops the most-repeated anchors first when a rarity function is supplied", () => {
    // 20 copies of a noisy repeated pattern plus 2 genuinely rare ones, all Critical, budget 6.
    const events = [
      ...Array.from({ length: 20 }, (_, i) => ev(`noise${i}`, `2026-05-20T10:${String(i).padStart(2, "0")}:00Z`, "Critical")),
      ev("rare1", "2026-05-20T11:00:00Z", "Critical"),
      ev("rare2", "2026-05-20T11:05:00Z", "Critical"),
    ];
    const rarityOf = (e: ForensicEvent): number => (e.id.startsWith("rare") ? 1 : 0.05);

    const ids = selectSynthesisEvents(events, 6, rarityOf).map((e) => e.id);
    expect(ids).toContain("rare1");
    expect(ids).toContain("rare2");
  });

  // The anchor-context scenario: `lead` filler occupies the 15 guaranteed EARLIEST seats so the
  // interesting events are claimed by the anchor-context fill (not by the earliest guarantee), and
  // `tail` filler pushes the timeline past the budget so the reserved fills actually run.
  function anchorScenario(...middle: ForensicEvent[]): ForensicEvent[] {
    const lead = Array.from({ length: 20 }, (_, i) =>
      host(ev(`lead${i}`, `2026-05-19T${String(i % 24).padStart(2, "0")}:30:00Z`, "Info"), "WIN-50"));
    const tail = Array.from({ length: 40 }, (_, i) =>
      host(ev(`tail${i}`, `2026-05-21T${String(i % 24).padStart(2, "0")}:30:00Z`, "Info"), "WIN-50"));
    return [...lead, ...middle, ...tail];
  }

  it("pulls same-host events within the anchor window in as context", () => {
    // A High anchor on WIN-01, with quiet Low events on WIN-01 inside the ±15min window, one WIN-01
    // event well OUTSIDE it, and same-time noise on an unrelated host.
    const events = anchorScenario(
      host(ev("anchor", "2026-05-20T12:00:00Z", "High"), "WIN-01"),
      host(ev("near-proc", "2026-05-20T12:05:00Z", "Low"), "WIN-01", "powershell.exe"),
      host(ev("near-plain", "2026-05-20T12:01:00Z", "Low"), "WIN-01"),
      host(ev("far-same-host", "2026-05-20T14:00:00Z", "Low"), "WIN-01"),
      host(ev("other-host", "2026-05-20T12:02:00Z", "Low"), "WIN-99"),
    );

    const { events: picked, classOf } = selectSynthesisEventsAnnotated(events, 40);
    expect(picked.map((e) => e.id)).toContain("anchor");
    expect(classOf.get("near-proc")).toBe("anchor_context");
    expect(classOf.get("near-plain")).toBe("anchor_context");
    // Out-of-window / other-host events can still win a later spread seat, so assert on the CLASS
    // rather than mere absence — that is what pins the window and the same-host rule.
    expect(classOf.get("far-same-host")).not.toBe("anchor_context");
    expect(classOf.get("other-host")).not.toBe("anchor_context");
  });

  it("prefers process-like events when an anchor has more context than its per-anchor share", () => {
    const events = anchorScenario(
      host(ev("anchor", "2026-05-20T12:00:00Z", "High"), "WIN-01"),
      host(ev("near-plain", "2026-05-20T12:01:00Z", "Low"), "WIN-01"),        // closer in time…
      host(ev("near-proc", "2026-05-20T12:05:00Z", "Low"), "WIN-01", "powershell.exe"), // …but this ran something
    );
    // max 19 = 1 anchor + 15 earliest + 3 remaining → a single anchor-context seat, so only the
    // best-ranked candidate can take it.
    const classOf = selectSynthesisEventsAnnotated(events, 19).classOf;
    expect(classOf.get("near-proc")).toBe("anchor_context");
    expect(classOf.get("near-plain")).not.toBe("anchor_context");
  });

  it("matches same-host context case-insensitively and ignoring surrounding whitespace", () => {
    const events = anchorScenario(
      host(ev("anchor", "2026-05-20T12:00:00Z", "High"), "WIN-01"),
      host(ev("padded", "2026-05-20T12:03:00Z", "Low"), "  win-01 "),
    );
    expect(selectSynthesisEventsAnnotated(events, 40).classOf.get("padded")).toBe("anchor_context");
  });

  // Complexity guard for the anchor-context fill, which used to re-scan the WHOLE timeline once per
  // anchor — cost growing with anchors × events. It only bites in the regime asserted below: the fill
  // runs solely while the Critical/High anchors FIT the budget (more anchors than `max` short-circuits
  // into the severity-trim branch), so the shape that hurts is a long timeline carrying a few hundred
  // genuine detections — an ordinary big case, not a pathological one.
  //
  // Both runs use the SAME timeline and differ only in how many events are graded High, which isolates
  // the defective term: 10× the anchors multiplied the old implementation's work by ~10, while a
  // windowed per-asset lookup leaves it essentially flat. Asserting that RATIO rather than a millisecond
  // bound keeps the test honest on a shared CI runner — machine speed cancels out instead of forcing a
  // threshold so loose it catches nothing.
  it("does not get proportionally slower as a timeline gains anchors", () => {
    const hosts = Array.from({ length: 20 }, (_, i) => `HOST-${i}`);
    const start = Date.parse("2026-05-20T00:00:00Z");
    const build = (anchorEvery: number): ForensicEvent[] =>
      Array.from({ length: 20_000 }, (_, i) => {
        const e = ev(`e${i}`, new Date(start + i * 30_000).toISOString(), i % anchorEvery === 0 ? "High" : "Low");
        e.description = `powershell.exe ran step ${i}`;
        return host(e, hosts[i % hosts.length]);
      });

    const fewAnchors = build(1000);    // 20 anchors
    const manyAnchors = build(100);    // 200 anchors
    // Preconditions: both stay under the budget (so neither takes the anchor-overflow short-circuit)
    // and both leave real budget for the context fill. If either flips, this silently stops measuring
    // the path it was written to measure.
    expect(manyAnchors.filter((e) => e.severity === "High").length).toBe(200);
    expect(fewAnchors.filter((e) => e.severity === "High").length).toBe(20);

    const timeOf = (evts: ForensicEvent[]): number => {
      let best = Infinity;
      for (let i = 0; i < 3; i++) {          // min-of-3 — the fastest run is the least noise-polluted
        const t0 = performance.now();
        selectSynthesisEvents(evts, 300);
        best = Math.min(best, performance.now() - t0);
      }
      return best;
    };

    timeOf(fewAnchors);                       // discarded: warm the JIT so neither run pays compilation
    // Measured: ~1.0 with the windowed lookup, 4.2–5.2 when each anchor rescans the timeline.
    expect(timeOf(manyAnchors) / timeOf(fewAnchors)).toBeLessThan(2);
  });
});

describe("buildSynthesisContext", () => {
  it("summarizes compromised assets and threat-intel verdicts", () => {
    const s = emptyState("c1");
    s.iocs.push({ id: "i1", type: "process", value: "evil.exe", firstSeen: "",
      enrichments: [{ source: "VirusTotal", verdict: "malicious", score: "52/73", fetchedAt: "" }] });
    s.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "evil.exe run", severity: "Critical",
      mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [], asset: "WIN-01" });
    s.findings.push({ id: "f1", severity: "Critical", title: "RW", description: "", relatedIocs: ["i1"],
      mitreTechniques: [], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "confirmed" });

    const ctx = buildSynthesisContext(s, s.forensicTimeline);
    expect(ctx).toContain("COMPROMISED ASSETS");
    expect(ctx).toContain("WIN-01 (host)");
    expect(ctx).toContain("evil.exe");
    expect(ctx).toContain("THREAT-INTEL VERDICTS");
    expect(ctx).toContain("evil.exe = malicious (VirusTotal 52/73)");
  });

  it("returns an empty string when there's nothing to add", () => {
    expect(buildSynthesisContext(emptyState("c1"), [])).toBe("");
  });

  it("flags a threat-intel verdict on the case's OWN host asset instead of trusting it silently", () => {
    const s = emptyState("c1");
    // db-01 is the case's own internal server (an event carries it as `asset`); a threat-intel
    // provider nonetheless marked the same value suspicious — likely stale/wrong data, not a real
    // external C2, and the model must not treat it as confirmed without saying so.
    s.iocs.push({ id: "i1", type: "domain", value: "db-01.northpeaklabs.com", firstSeen: "",
      enrichments: [{ source: "OpenCTI", verdict: "suspicious", score: "", fetchedAt: "" }] });
    s.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "connection to db-01.northpeaklabs.com",
      severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "db-01.northpeaklabs.com" });

    const ctx = buildSynthesisContext(s, s.forensicTimeline);
    // #7: a conflicted verdict (own-host asset) is moved to the dedicated INTEL CONFLICTS block so the
    // model can't read it as confirmed external C2 — not the trusted THREAT-INTEL VERDICTS list.
    expect(ctx).toContain("INTEL CONFLICTS");
    expect(ctx).toContain("db-01.northpeaklabs.com = suspicious (OpenCTI)");
    expect(ctx).toContain("CONFLICT");
    expect(ctx).toContain("also one of this case's OWN host assets");
  });

  it("tags a corroborated verdict (provider + behavioral event) as [corroborated]", () => {
    const s = emptyState("c1");
    s.iocs.push({ id: "i1", type: "process", value: "evil.exe", firstSeen: "",
      enrichments: [{ source: "VirusTotal", verdict: "malicious", score: "52/73", fetchedAt: "" }] });
    s.forensicTimeline.push({ id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "evil.exe run", severity: "Critical",
      mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WIN-01" });
    const ctx = buildSynthesisContext(s, s.forensicTimeline);
    expect(ctx).toContain("THREAT-INTEL VERDICTS");
    expect(ctx).toContain("evil.exe = malicious (VirusTotal 52/73) [corroborated]");
  });

  it("tags a single-provider verdict with no behavioral evidence as [lone-intel]", () => {
    const s = emptyState("c1");
    s.iocs.push({ id: "i1", type: "domain", value: "evil-c2.example", firstSeen: "",
      enrichments: [{ source: "VirusTotal", verdict: "suspicious", score: "", fetchedAt: "" }] });
    const ctx = buildSynthesisContext(s, s.forensicTimeline);
    expect(ctx).toContain("[lone-intel]");
  });
});
