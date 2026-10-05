import { describe, it, expect } from "vitest";
import {
  attackerGradedInterval,
  classifyGapEdges,
  provisioningReason,
  severeAssetsOf,
} from "../../src/analysis/gapEdgeClass.js";
import { detectTimelineGaps, backfillSilenceGapFindings } from "../../src/analysis/gapDetect.js";
import {
  backfillActivityWaveFinding,
  detectActivityWaves,
  detectGapsWithWaves,
  markWaveBoundaries,
} from "../../src/analysis/activityWaves.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: extra.relatedFindingIds ?? [],
    sourceScreenshots: [],
    sources: ["velo"],
    ...extra,
  };
}

function burst(
  prefix: string,
  startISO: string,
  count: number,
  extra: Partial<ForensicEvent> = {},
): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  let ms = Date.parse(startISO);
  for (let i = 0; i < count; i++) {
    out.push(ev(`${prefix}${i}`, new Date(ms).toISOString(), extra));
    ms += 60_000;
  }
  return out;
}

describe("provisioningReason", () => {
  it("recognises servicing and image-build artifacts graded Info", () => {
    expect(
      provisioningReason(
        ev("a", "2025-12-05T10:00:00Z", { path: "c:\\programdata\\chocolatey\\lib\\git\\tools\\git.exe" }),
      ),
    ).toBe("chocolatey");
    expect(
      provisioningReason(
        ev("b", "2025-12-05T10:00:00Z", {
          description: "Amcache: C:\\Windows\\servicing\\TrustedInstaller.exe",
        }),
      ),
    ).toBe("servicing");
    expect(provisioningReason(ev("c", "2025-12-05T10:00:00Z", { processName: "TiWorker.exe" }))).toBe(
      "servicing",
    );
    expect(
      provisioningReason(
        ev("d", "2025-12-05T10:00:00Z", { path: "c:\\windows\\softwaredistribution\\download\\x.cab" }),
      ),
    ).toBe("windows-update");
    expect(
      provisioningReason(ev("e", "2025-12-05T10:00:00Z", { path: "c:\\windows\\panther\\unattend.xml" })),
    ).toBe("sysprep/unattend");
    expect(
      provisioningReason(
        ev("f", "2025-12-05T10:00:00Z", { description: "C:\\vagrant\\bootstrap.ps1 executed" }),
      ),
    ).toBe("vagrant");
  });

  it("never reads a graded, tagged or finding-backed row as provisioning", () => {
    const path = "c:\\programdata\\chocolatey\\lib\\nmap\\tools\\nmap.exe";
    expect(provisioningReason(ev("a", "2025-12-05T10:00:00Z", { path, severity: "High" }))).toBeNull();
    expect(provisioningReason(ev("b", "2025-12-05T10:00:00Z", { path, severity: "Medium" }))).toBeNull();
    expect(
      provisioningReason(ev("c", "2025-12-05T10:00:00Z", { path, mitreTechniques: ["T1046"] })),
    ).toBeNull();
    expect(
      provisioningReason(ev("d", "2025-12-05T10:00:00Z", { path, relatedFindingIds: ["f3"] })),
    ).toBeNull();
  });

  it("ignores a link to a finding that gap analysis itself minted", () => {
    const path = "c:\\windows\\winsxs\\manifests\\x.manifest";
    expect(
      provisioningReason(
        ev("a", "2025-12-05T10:00:00Z", { path, relatedFindingIds: ["f-gap-a-b", "f-waves"] }),
      ),
    ).toBe("servicing");
  });

  it("does not treat dual-use installers as provisioning", () => {
    expect(
      provisioningReason(ev("a", "2025-12-05T10:00:00Z", { description: "msiexec.exe /i payload.msi /qn" })),
    ).toBeNull();
    expect(
      provisioningReason(ev("b", "2025-12-05T10:00:00Z", { path: "c:\\users\\bob\\downloads\\setup.exe" })),
    ).toBeNull();
  });
});

describe("attackerGradedInterval", () => {
  it("needs a High/Critical row on both sides", () => {
    expect(attackerGradedInterval(new Set(["HOST-A"]), new Set())).toBe(false);
    expect(attackerGradedInterval(new Set(), new Set(["HOST-A"]))).toBe(false);
  });

  it("needs a common asset when both sides name one", () => {
    expect(attackerGradedInterval(new Set(["HOST-A"]), new Set(["HOST-B"]))).toBe(false);
    expect(attackerGradedInterval(new Set(["HOST-A", "HOST-B"]), new Set(["HOST-B"]))).toBe(true);
  });

  it("lets an unattributed severe row match any host", () => {
    expect(attackerGradedInterval(new Set([""]), new Set(["HOST-B"]))).toBe(true);
  });

  it("collects severe assets by short host name", () => {
    const wave = [
      ev("a", "2026-08-17T10:00:00Z", { severity: "High", asset: "desktop-16ojfo6.example.com" }),
      ev("b", "2026-08-17T10:01:00Z", { severity: "Medium", asset: "OTHER" }),
      ev("c", "2026-08-17T10:02:00Z", { severity: "Critical" }),
    ];
    expect([...severeAssetsOf(wave)].sort()).toEqual(["", "DESKTOP-16OJFO6"]);
  });
});

describe("classifyGapEdges", () => {
  const svc = { path: "c:\\windows\\softwaredistribution\\download\\a.cab" };

  it("marks a silence between two servicing rows as provisioning idle time", () => {
    const events = [
      ...burst("w1-", "2025-12-05T10:00:00Z", 4, svc),
      ...burst("w2-", "2025-12-05T20:00:00Z", 4, svc),
    ];
    const gaps = detectTimelineGaps(events);
    expect(gaps).toHaveLength(1);
    const [g] = classifyGapEdges(gaps, events, null);
    expect(g.provisioningEdges).toBe(true);
    expect(g.provisioningReason).toBe("windows-update");
  });

  it("leaves a silence alone when only one edge is a servicing row", () => {
    const events = [
      ...burst("w1-", "2025-12-05T10:00:00Z", 4, svc),
      ...burst("w2-", "2025-12-05T20:00:00Z", 4, { description: "cmd.exe /c whoami" }),
    ];
    const [g] = classifyGapEdges(detectTimelineGaps(events), events, null);
    expect(g.provisioningEdges).toBeUndefined();
  });

  it("marks attackerEdges only on a dwell interval between two graded waves", () => {
    const events = [
      ...burst("w1-", "2026-08-07T14:30:00Z", 6, { asset: "HOST-A", severity: "High" }),
      ...burst("w2-", "2026-08-25T17:30:00Z", 6, { asset: "HOST-A" }),
      ...burst("w3-", "2026-08-26T13:45:00Z", 6, { asset: "HOST-A", severity: "High" }),
    ];
    const raw = detectTimelineGaps(events);
    const pattern = detectActivityWaves(events, raw)!;
    expect(pattern.intervals.map((iv) => iv.attackerGraded)).toEqual([false, false]);
    const gaps = classifyGapEdges(markWaveBoundaries(raw, pattern), events, pattern);
    expect(gaps.every((g) => g.betweenWaves && g.attackerEdges === false)).toBe(true);
  });

  it("does not let a High on one host and a High on another make a dwell interval", () => {
    const events = [
      ...burst("w1-", "2026-08-07T14:30:00Z", 6, { asset: "HOST-A", severity: "High" }),
      ...burst("w2-", "2026-08-25T17:30:00Z", 6, { asset: "HOST-B", severity: "High" }),
    ];
    const { gaps, pattern } = detectGapsWithWaves(events);
    expect(pattern!.intervals[0].attackerGraded).toBe(false);
    expect(gaps[0].attackerEdges).toBe(false);
  });
});

describe("classifyGapEdges precedence", () => {
  it("lets attacker-graded waves win over two idle edge rows", () => {
    const svc = { path: "c:\\windows\\softwaredistribution\\download\\a.cab" };
    const events = [
      ev("h1", "2026-08-07T14:29:00Z", { asset: "HOST-A", severity: "High" }),
      ...burst("w1-", "2026-08-07T14:30:00Z", 4, { asset: "HOST-A", ...svc }),
      ...burst("w2-", "2026-08-25T17:30:00Z", 4, { asset: "HOST-A", ...svc }),
      ev("h2", "2026-08-25T17:34:00Z", { asset: "HOST-A", severity: "Critical" }),
    ];
    const { gaps, pattern } = detectGapsWithWaves(events);
    expect(pattern!.intervals[0].attackerGraded).toBe(true);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].attackerEdges).toBe(true);
    expect(gaps[0].provisioningEdges).toBeUndefined();
  });
});

describe("findings from classified gaps", () => {
  it("emits no dwell finding and no waves finding for benign bursts months apart", () => {
    // The scenario 017 shape: install media → base image → provisioning → first session, all Info.
    const events = [
      ...burst("iso-", "2024-04-01T00:00:00Z", 5, {
        asset: "DESKTOP-16OJFO6",
        path: "c:\\windows\\winsxs\\x.manifest",
      }),
      ...burst("img-", "2025-09-15T08:00:00Z", 5, {
        asset: "DESKTOP-16OJFO6",
        path: "c:\\windows\\system32\\driverstore\\x.inf",
      }),
      ...burst("prov-", "2025-12-05T09:00:00Z", 8, {
        asset: "DESKTOP-16OJFO6",
        path: "c:\\programdata\\chocolatey\\lib\\x\\y.exe",
      }),
      ...burst("use-", "2026-08-17T10:00:00Z", 6, {
        asset: "DESKTOP-16OJFO6",
        description: "explorer.exe started",
      }),
    ];
    const { gaps, pattern } = detectGapsWithWaves(events);
    expect(pattern).not.toBeNull();
    // Two of the three silences sit between servicing rows and vanish from every surface.
    expect(gaps).toHaveLength(1);
    expect(gaps[0].betweenWaves).toBe(true);
    expect(gaps[0].attackerEdges).toBe(false);
    const base = { ...emptyState("INC-TEST"), forensicTimeline: events };
    const withWaves = backfillActivityWaveFinding(base, pattern, "2026-08-26T20:00:00Z");
    const state = backfillSilenceGapFindings(withWaves, gaps, "2026-08-26T20:00:00Z");
    expect(state.findings).toHaveLength(0);
  });

  it("keeps the Medium dwell finding and the waves finding between two attacker-graded waves", () => {
    const events = [
      ...burst("w1-", "2026-08-07T14:30:00Z", 6, { asset: "HOST-A", severity: "High" }),
      ...burst("w2-", "2026-08-25T17:30:00Z", 6, { asset: "host-a.corp.example.com", severity: "Critical" }),
    ];
    const { gaps, pattern } = detectGapsWithWaves(events);
    const base = { ...emptyState("INC-TEST"), forensicTimeline: events };
    const withWaves = backfillActivityWaveFinding(base, pattern, "2026-08-26T20:00:00Z");
    const state = backfillSilenceGapFindings(withWaves, gaps, "2026-08-26T20:00:00Z");
    expect(state.findings.map((f) => f.id)).toContain("f-waves");
    const dwell = state.findings.find((f) => f.id.startsWith("f-gap-"))!;
    expect(dwell.title).toContain("Dwell interval");
    expect(dwell.severity).toBe("Medium");
  });

  it("builds the waves finding from attacker-graded wave pairs only", () => {
    // Two benign build bursts, then two attacker waves: the finding counts, spans and links the
    // attacker pair alone.
    const events = [
      ...burst("b1-", "2025-09-15T08:00:00Z", 5, { asset: "HOST-A" }),
      ...burst("b2-", "2025-12-05T09:00:00Z", 5, { asset: "HOST-A" }),
      ...burst("a1-", "2026-08-07T14:30:00Z", 6, { asset: "HOST-A", severity: "High" }),
      ...burst("a2-", "2026-08-25T17:30:00Z", 6, { asset: "HOST-A", severity: "High" }),
    ];
    const { pattern } = detectGapsWithWaves(events);
    expect(pattern!.waves).toHaveLength(4);
    const state = backfillActivityWaveFinding(
      { ...emptyState("INC-TEST"), forensicTimeline: events },
      pattern,
      "2026-08-26T20:00:00Z",
    );
    const f = state.findings.find((x) => x.id === "f-waves")!;
    expect(f.title).toContain("2 separate waves");
    expect(f.title).toContain("spanning 18d");
    expect(f.description).not.toContain("2025-09-15");
    expect(f.description).toContain("wave 3");
    const linked = state.forensicTimeline
      .filter((e) => e.relatedFindingIds.includes("f-waves"))
      .map((e) => e.id);
    expect(linked).toEqual(["a1-0", "a1-5", "a2-0", "a2-5"]);
  });

  it("still escalates an unexplained complete silence between two ordinary rows", () => {
    const events = [
      ...burst("w1-", "2026-08-07T14:30:00Z", 6, { description: "svchost.exe" }),
      ev("lone", "2026-08-25T17:30:00Z", { description: "cmd.exe" }),
    ];
    const { gaps } = detectGapsWithWaves(events);
    const state = backfillSilenceGapFindings(
      { ...emptyState("INC-TEST"), forensicTimeline: events },
      gaps,
      "2026-08-26T20:00:00Z",
    );
    expect(state.findings).toHaveLength(1);
    expect(state.findings[0].title).toContain("coverage gap");
  });
});

// #1942: a complete gap is High only with corroboration — a Medium-or-higher row at either edge, or
// a real anti-forensic event in the case (log cleared 1102/104, audit policy changed 4719). An idle
// lab VM's silence is Low and says so. A reboot or shutdown at the gap edge explains the silence.
describe("complete-gap grade (#1942)", () => {
  // Two short bursts 5h 50m apart — the issue's idle lab VM. Under the 6h wave threshold, so the
  // silence stays a plain complete gap rather than a dwell interval.
  const NOW = "2025-12-05T16:00:00Z";
  const IN_BURST = "2025-12-05T09:57:30Z";
  function idleCase(
    beforeEdge: Partial<ForensicEvent> = {},
    afterEdge: Partial<ForensicEvent> = {},
    extra: ForensicEvent[] = [],
  ): ForensicEvent[] {
    const before = burst("b", "2025-12-05T09:56:00Z", 4);
    const last = before[before.length - 1];
    before[before.length - 1] = ev(last.id, last.timestamp, beforeEdge);
    const after = burst("a", "2025-12-05T15:50:00Z", 4);
    after[0] = ev(after[0].id, after[0].timestamp, afterEdge);
    return [...before, ...after, ...extra];
  }
  function onlyGap(events: ForensicEvent[]) {
    const { gaps } = detectGapsWithWaves(
      events,
      { activeHours: null, densityFactor: 4 },
      { minWaveEvents: 3, minWaveIntervalHours: 6 },
    );
    const complete = gaps.filter((g) => g.complete && !g.betweenWaves);
    expect(complete).toHaveLength(1);
    return { gaps, gap: complete[0] };
  }
  function findingFor(events: ForensicEvent[]) {
    const { gaps } = onlyGap(events);
    const s = backfillSilenceGapFindings({ ...emptyState("c"), forensicTimeline: events }, gaps, NOW);
    expect(s.findings).toHaveLength(1);
    return s.findings[0];
  }

  it("grades an idle gap with benign edges and no clear event Low, as a lead without T1070", () => {
    const events = idleCase({ severity: "Low" }, { severity: "Info" });
    expect(onlyGap(events).gap.severity).toBe("Low");
    const f = findingFor(events);
    expect(f.severity).toBe("Low");
    expect(f.description).toContain("a lead, not proof");
    expect(f.description).not.toMatch(/classic (?:signature|indicator)/);
    expect(f.mitreTechniques).toEqual([]);
  });

  it("grades a gap next to a Medium-or-higher row High, with the tampering text and T1070", () => {
    const pairs: Array<[Partial<ForensicEvent>, Partial<ForensicEvent>]> = [
      [{ severity: "High" }, {}],
      [{}, { severity: "Medium" }],
    ];
    for (const [b, a] of pairs) {
      const events = idleCase(b, a);
      expect(onlyGap(events).gap.severity).toBe("High");
      const f = findingFor(events);
      expect(f.severity).toBe("High");
      expect(f.description).toContain("classic indicator of log tampering");
      expect(f.mitreTechniques).toEqual(["T1070"]);
    }
  });

  it("grades a gap High when the case records a log clear or an audit-policy change", () => {
    const clears = [
      ev("x1", IN_BURST, { description: "Security audit log cleared (EID 1102)" }),
      ev("x2", IN_BURST, { description: "System: EventID 104 — The System log file was cleared." }),
      ev("x3", IN_BURST, { description: "Sigma: Eventlog Cleared (Event ID 104)" }),
      ev("x4", IN_BURST, { description: "System audit policy changed (EID 4719)" }),
      ev("x5", IN_BURST, { description: "auditpol.exe /clear", mitreTechniques: ["T1562.002"] }),
    ];
    for (const c of clears) {
      const events = idleCase({}, {}, [c]);
      expect(onlyGap(events).gap.severity, c.description).toBe("High");
      expect(findingFor(events).severity).toBe("High");
    }
  });

  it("does not read an EID number inside another number as a clear event", () => {
    const events = idleCase({}, {}, [ev("x", IN_BURST, { description: "EID 11020 telemetry" })]);
    expect(onlyGap(events).gap.severity).toBe("Low");
  });

  it("explains a gap that opens on a reboot or shutdown: Low, and the text names the reboot", () => {
    const boot = { canonical: { event: { category: "other", type: "boot" } } } as Partial<ForensicEvent>;
    const edges: Partial<ForensicEvent>[] = [
      boot,
      {
        description: "User32: The process shutdown.exe has initiated the restart of computer WS01 (EID 1074)",
      },
      { description: "Event log service stopped (EID 6006)", severity: "Low" },
    ];
    for (const edge of edges) {
      const events = idleCase(edge);
      const { gap } = onlyGap(events);
      expect(gap.rebootEdge).toBe(true);
      expect(gap.severity).toBe("Low");
      const f = findingFor(events);
      expect(f.severity).toBe("Low");
      expect(f.description).toMatch(/reboot or shutdown/i);
      expect(f.description).not.toMatch(/classic (?:signature|indicator)/);
      expect(f.mitreTechniques).toEqual([]);
    }
    // An event-log service start (6005) at the resume edge is the same reboot seen from the far side.
    const resumed = idleCase({}, { description: "Event log service started (EID 6005)" });
    expect(onlyGap(resumed).gap.rebootEdge).toBe(true);
  });

  it("is deterministic: the same input grades and words the gap the same way twice", () => {
    const events = idleCase({ severity: "Low" }, {});
    expect(onlyGap(events).gaps).toEqual(onlyGap(events).gaps);
    expect(findingFor(events)).toEqual(findingFor(events));
  });

  it("leaves partial gaps and dwell intervals at their existing grades", () => {
    const events = idleCase();
    const raw = detectTimelineGaps(events, { activeHours: null, densityFactor: 4 });
    const partial = { ...raw[0], id: "gap-x", complete: false, severity: "Medium" as const };
    const dwell = { ...raw[0], id: "gap-y", severity: "High" as const, betweenWaves: true };
    const out = classifyGapEdges([partial, dwell], events, null);
    expect(out[0].severity).toBe("Medium");
    expect(out[1].severity).toBe("High");
  });
});
