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
