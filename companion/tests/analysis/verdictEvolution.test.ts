import { describe, it, expect } from "vitest";
import {
  computeVerdictHistories,
  detectVerdictChanges,
  nextRunAtFor,
  selectIocsDueForRecheck,
  formatChangeMessage,
  DEFAULT_VERDICT_EVOLUTION_CONFIG,
  type IocVerdictHistory,
  type VerdictSample,
} from "../../src/analysis/verdictEvolution.js";
import type { IOC, IocEnrichment } from "../../src/analysis/stateTypes.js";

function enrich(source: string, verdict: IocEnrichment["verdict"], fetchedAt: string, extra: Partial<IocEnrichment> = {}): IocEnrichment {
  return { source, verdict, fetchedAt, ...extra };
}

function ioc(id: string, value: string, enrichments: IocEnrichment[] = [], type: IOC["type"] = "ip"): IOC {
  return { id, type, value, firstSeen: "2026-01-01T00:00:00Z", enrichments };
}

function sample(ts: string, provider: string, verdict: VerdictSample["verdict"], detections?: number, score?: string): VerdictSample {
  return { ts, provider, verdict, detections, score };
}

describe("computeVerdictHistories", () => {
  it("builds a per-IOC timestamped history ordered oldest → newest", () => {
    const iocs = [
      ioc("i1", "5.6.7.8", [
        enrich("VirusTotal", "harmless", "2026-04-01T00:00:00Z", { detections: 2, total: 60, score: "2/60" }),
        enrich("VirusTotal", "suspicious", "2026-04-15T00:00:00Z", { detections: 12, total: 60, score: "12/60" }),
        enrich("VirusTotal", "malicious", "2026-04-22T00:00:00Z", { detections: 47, total: 60, score: "47/60" }),
      ]),
    ];
    const h = computeVerdictHistories(iocs);
    expect(h).toHaveLength(1);
    expect(h[0].iocId).toBe("i1");
    expect(h[0].samples.map((s) => s.verdict)).toEqual(["harmless", "suspicious", "malicious"]);
    expect(h[0].samples.map((s) => s.ts)).toEqual([
      "2026-04-01T00:00:00Z",
      "2026-04-15T00:00:00Z",
      "2026-04-22T00:00:00Z",
    ]);
  });

  it("skips IOCs with no enrichments and groups by owning provider", () => {
    const iocs = [
      ioc("i1", "1.2.3.4", []),
      ioc("i2", "evil.com", [
        enrich("MalwareBazaar", "malicious", "2026-05-01T00:00:00Z", { provider: "Hunting.ch" }),
      ]),
    ];
    const h = computeVerdictHistories(iocs);
    expect(h).toHaveLength(1);
    expect(h[0].iocId).toBe("i2");
    expect(h[0].samples[0].provider).toBe("Hunting.ch");
  });

  it("is pure — does not mutate the input IOCs", () => {
    const iocs = [ioc("i1", "5.6.7.8", [enrich("VT", "harmless", "2026-04-01T00:00:00Z")])];
    const before = JSON.stringify(iocs);
    computeVerdictHistories(iocs);
    expect(JSON.stringify(iocs)).toBe(before);
  });
});

describe("detectVerdictChanges", () => {
  const prev: IocVerdictHistory[] = [
    { iocId: "i1", value: "5.6.7.8", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "harmless", 2, "2/60")] },
  ];

  it("detects an escalation (harmless → malicious) with a newer sample", () => {
    const current: IocVerdictHistory[] = [
      { iocId: "i1", value: "5.6.7.8", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "harmless", 2, "2/60"), sample("2026-04-22T00:00:00Z", "VirusTotal", "malicious", 47, "47/60")] },
    ];
    const changes = detectVerdictChanges(prev, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe("escalation");
    expect(changes[0].message).toContain("5.6.7.8");
    expect(changes[0].message).toContain("harmless→malicious");
    expect(changes[0].message).toContain("VirusTotal");
  });

  it("detects a deescalation (malicious → harmless)", () => {
    const prevMal: IocVerdictHistory[] = [
      { iocId: "i1", value: "5.6.7.8", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "malicious", 47, "47/60")] },
    ];
    const current: IocVerdictHistory[] = [
      { iocId: "i1", value: "5.6.7.8", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "malicious", 47, "47/60"), sample("2026-04-22T00:00:00Z", "VirusTotal", "harmless", 2, "2/60")] },
    ];
    const changes = detectVerdictChanges(prevMal, current);
    expect(changes[0].kind).toBe("deescalation");
  });

  it("detects a score-delta change when verdict is unchanged but detections delta ≥ threshold", () => {
    const current: IocVerdictHistory[] = [
      { iocId: "i1", value: "5.6.7.8", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "harmless", 2, "2/60"), sample("2026-04-22T00:00:00Z", "VirusTotal", "harmless", 12, "12/60")] },
    ];
    const changes = detectVerdictChanges(prev, current, { scoreDeltaThreshold: 5 });
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe("score-delta");
    expect(changes[0].message).toContain("score changed 2/60→12/60");
  });

  it("does not emit a score-delta change below the threshold", () => {
    const current: IocVerdictHistory[] = [
      { iocId: "i1", value: "5.6.7.8", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "harmless", 2, "2/60"), sample("2026-04-22T00:00:00Z", "VirusTotal", "harmless", 4, "4/60")] },
    ];
    const changes = detectVerdictChanges(prev, current, { scoreDeltaThreshold: 5 });
    expect(changes).toHaveLength(0);
  });

  it("ignores a sample that is not newer than the previous one (no re-check)", () => {
    const current: IocVerdictHistory[] = [
      { iocId: "i1", value: "5.6.7.8", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "malicious", 47, "47/60")] },
    ];
    const changes = detectVerdictChanges(prev, current);
    expect(changes).toHaveLength(0);
  });

  it("ignores IOCs that have no previous history (first enrichment)", () => {
    const current: IocVerdictHistory[] = [
      { iocId: "i2", value: "9.9.9.9", type: "ip", samples: [sample("2026-04-01T00:00:00Z", "VirusTotal", "malicious", 47, "47/60")] },
    ];
    const changes = detectVerdictChanges(prev, current);
    expect(changes).toHaveLength(0);
  });

  it("formatChangeMessage produces a readable one-liner", () => {
    const msg = formatChangeMessage("evil.com", "MISP", sample("2026-04-01T00:00:00Z", "MISP", "harmless"), sample("2026-04-22T00:00:00Z", "MISP", "suspicious"), "escalation");
    expect(msg).toBe("IOC evil.com MISP verdict changed harmless→suspicious (n/a→n/a).");
  });
});

describe("nextRunAtFor", () => {
  it("returns an empty string when disabled", () => {
    expect(nextRunAtFor({ ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: false })).toBe("");
  });

  it("returns now + intervalDays when enabled", () => {
    const now = new Date("2026-07-25T00:00:00Z");
    const next = nextRunAtFor({ ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: true, intervalDays: 7 }, now);
    expect(next).toBe("2026-08-01T00:00:00.000Z");
  });

  it("clamps a sub-1-day interval to 1 day", () => {
    const now = new Date("2026-07-25T00:00:00Z");
    const next = nextRunAtFor({ ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: true, intervalDays: 0 }, now);
    expect(next).toBe("2026-07-26T00:00:00.000Z");
  });
});

describe("selectIocsDueForRecheck", () => {
  const now = new Date("2026-07-25T00:00:00Z");
  const iocs = [
    ioc("i1", "5.6.7.8", [enrich("VirusTotal", "harmless", "2026-04-01T00:00:00Z", { detections: 2 })]),
    ioc("i2", "evil.com", [enrich("VirusTotal", "malicious", "2026-07-24T00:00:00Z", { detections: 47 })]),
    ioc("i3", "no-history.com", [enrich("VirusTotal", "harmless", "2026-07-01T00:00:00Z", { detections: 0 })]),
  ];
  const histories = computeVerdictHistories(iocs);
  const findings = [
    { id: "f1", severity: "High" as const, relatedIocs: ["i1", "i2", "i3"], status: "open" },
  ];

  it("selects an unresolved IOC whose latest sample is older than intervalDays", () => {
    const due = selectIocsDueForRecheck(iocs, histories, findings, { ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: true, intervalDays: 7, maliciousIntervalDays: 30, minSeverity: "Low" }, now);
    // i1: harmless, last seen 2026-04-01 → way past 7d → due
    // i2: malicious, last seen 2026-07-24 → not yet 30d → not due
    // i3: harmless, last seen 2026-07-01 → past 7d → due
    const dueIds = due.map((d) => d.id);
    expect(dueIds).toContain("i1");
    expect(dueIds).toContain("i3");
    expect(dueIds).not.toContain("i2");
  });

  it("respects the minSeverity filter (an IOC only on an Info finding is skipped when minSeverity=High)", () => {
    const lowFindings = [{ id: "f1", severity: "Info" as const, relatedIocs: ["i1"], status: "open" }];
    const due = selectIocsDueForRecheck(iocs, histories, lowFindings, { ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: true, intervalDays: 7, maliciousIntervalDays: 30, minSeverity: "High" }, now);
    expect(due).toHaveLength(0);
  });

  it("skips IOCs with no enrichment history", () => {
    const noHist = ioc("i4", "fresh.com", []);
    const due = selectIocsDueForRecheck([noHist], [], [{ id: "f1", severity: "High", relatedIocs: ["i4"], status: "open" }], { ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: true, intervalDays: 7, maliciousIntervalDays: 30, minSeverity: "Low" }, now);
    expect(due).toHaveLength(0);
  });

  it("applies the longer maliciousIntervalDays to confirmed-malicious IOCs", () => {
    // i2 was malicious on 2026-07-24. With maliciousIntervalDays=30 it's not due on 2026-07-25.
    const due = selectIocsDueForRecheck(iocs, histories, findings, { ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: true, intervalDays: 7, maliciousIntervalDays: 30, minSeverity: "Low" }, now);
    expect(due.map((d) => d.id)).not.toContain("i2");
    // But with maliciousIntervalDays=0 (clamped to 1) it would be due — verify the interval is
    // actually applied by checking a date far enough in the future.
    const future = new Date("2026-09-25T00:00:00Z");
    const dueFuture = selectIocsDueForRecheck(iocs, histories, findings, { ...DEFAULT_VERDICT_EVOLUTION_CONFIG, enabled: true, intervalDays: 7, maliciousIntervalDays: 30, minSeverity: "Low" }, future);
    expect(dueFuture.map((d) => d.id)).toContain("i2");
  });
});