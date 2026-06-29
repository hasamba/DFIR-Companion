import { describe, it, expect, beforeAll } from "vitest";
import { emptyState, type ForensicEvent, type IOC, type InvestigationState, type Severity } from "../../src/analysis/stateTypes.js";
import { selectSynthesisEvents, buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { filterEventsByScope } from "../../src/analysis/scope.js";
import { applyLegitimate, type LegitimateMarker } from "../../src/analysis/legitimate.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";

// Performance / load test for issue #183: a synthetic 10k-event case exercising the hot
// deterministic paths. No AI calls, no I/O, no network — pure in-memory benchmarking.
// Thresholds are generous enough for slow CI runners but will catch a quadratic regression
// (10k^2 would blow past them by orders of magnitude).

const TARGET_EVENT_COUNT = 10_000;
const TARGET_IOC_COUNT = 500;

const HOSTS = [
  "DC01.corp.local", "WEB01.corp.local", "SQL01.corp.local", "WKSTN-01", "WKSTN-02",
  "WKSTN-03", "WKSTN-04", "WKSTN-05", "FILE01", "MAIL01",
  "LAPTOP-ADMIN", "SRV-PROD-01", "SRV-PROD-02", "SRV-PROD-03", "SRV-PROD-04",
  "SRV-PROD-05", "SRV-PROD-06", "SRV-PROD-07", "SRV-PROD-08", "SRV-PROD-09",
];

const SOURCES = ["THOR", "Velociraptor", "SIEM", "Hayabusa", "Chainsaw", "Suricata"];

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const SEV_WEIGHTS = [0.02, 0.08, 0.2, 0.3, 0.4];

const TECHNIQUES = [
  "T1566.001", "T1566.002", "T1078", "T1059.001", "T1059.003", "T1053.005",
  "T1547.001", "T1055", "T1003.001", "T1003.002", "T1021.002", "T1041",
  "T1071.001", "T1105", "T1490", "T1486", "T1083", "T1218.011",
];

const PROCESS_NAMES = [
  "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "excel.exe",
  "winword.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "schtasks.exe",
];

const PATHS = [
  "C:\\Windows\\System32\\svchost.exe",
  "C:\\Users\\Public\\update.exe",
  "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.vbs",
  "C:\\Windows\\Temp\\dropper.ps1",
  "C:\\Users\\jdoe\\AppData\\Roaming\\evil\\payload.dll",
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "C:\\Users\\svc_sql\\Documents\\run.bat",
  "C:\\Windows\\Tasks\\nightly.job",
];

const DOMAINS = [
  "evil-c2.example", "update-service.net", "cdn-analytics.io", "secure-login.org",
  "file-dropper.xyz", "news-breach.info", "ms-office-update.com",
];

const EXTERNAL_IPS = [
  "185.220.101.42", "45.142.212.89", "91.219.236.12", "198.51.100.7",
  "203.0.113.55", "192.0.2.30", "104.21.32.11", "172.67.178.22",
];

const INTERNAL_IPS = [
  "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14",
  "10.0.0.15", "10.0.0.16", "10.0.0.17", "10.0.0.18", "10.0.0.19",
];

function sha256FromSeed(seed: number): string {
  // Deterministic 64-hex "hash" — not cryptographically real, but structurally valid.
  return Array.from({ length: 64 }, (_, i) => {
    const n = (seed * 9301 + 49297 + i * 17) % 16;
    return Math.abs(n).toString(16);
  }).join("");
}

function pickWeighted<T>(items: T[], weights: number[], seed: number): T {
  const total = weights.reduce((a, b) => a + b, 0);
  let r = (seed % 1000) / 1000 * total;
  for (let i = 0; i < items.length; i++) {
    r -= weights[i];
    if (r <= 0) return items[i];
  }
  return items[items.length - 1];
}

function pick<T>(items: T[], seed: number): T {
  return items[Math.abs(seed) % items.length];
}

function isoAtMinutes(start: Date, minutes: number): string {
  return new Date(start.getTime() + minutes * 60_000).toISOString();
}

function buildSyntheticState(): InvestigationState {
  const state = emptyState("load-test-10k");
  const start = new Date("2026-06-15T00:00:00.000Z");

  // IOCs first so events can reference them.
  for (let i = 0; i < TARGET_IOC_COUNT; i++) {
    const seed = i * 997 + 1;
    const kind = i % 7;
    let type: IOC["type"];
    let value: string;
    if (kind === 0) { type = "ip"; value = pick(EXTERNAL_IPS.concat(INTERNAL_IPS), seed); }
    else if (kind === 1) { type = "domain"; value = pick(DOMAINS, seed); }
    else if (kind === 2) { type = "hash"; value = sha256FromSeed(seed); }
    else if (kind === 3) { type = "process"; value = pick(PROCESS_NAMES, seed); }
    else if (kind === 4) { type = "file"; value = pick(PATHS, seed); }
    else if (kind === 5) { type = "url"; value = `https://${pick(DOMAINS, seed)}/path${i % 20}`; }
    else { type = "other"; value = `ioc-${i}`; }

    state.iocs.push({
      id: `ioc-${i}`,
      type,
      value,
      firstSeen: isoAtMinutes(start, i),
      enrichments: i % 5 === 0 ? [{
        source: "VirusTotal",
        verdict: i % 3 === 0 ? "malicious" : "suspicious",
        score: `${(i % 50) + 1}/73`,
        fetchedAt: isoAtMinutes(start, i),
      }] : undefined,
    });
  }

  for (let i = 0; i < TARGET_EVENT_COUNT; i++) {
    const seed = i * 7919 + 13;
    const severity = pickWeighted(SEVERITIES, SEV_WEIGHTS, seed);
    const host = pick(HOSTS, seed);
    const source = pick(SOURCES, seed + 1);
    const minutes = i * 1.5 + (seed % 3);
    const ts = isoAtMinutes(start, minutes);
    const technique = pick(TECHNIQUES, seed + 2);

    // Mix event shapes so correlation, asset graph, evidence graph, beacon detection,
    // and anomaly detection all get realistic input.
    const shape = i % 5;
    let description: string;
    let action: ForensicEvent["action"] | undefined;
    let sha256: string | undefined;
    let md5: string | undefined;
    let path: string | undefined;
    let processName: string | undefined;
    let parentName: string | undefined;
    let srcIp: string | undefined;
    let dstIp: string | undefined;
    let port: number | undefined;

    if (shape === 0) {
      // Process execution / LOLBin
      processName = pick(PROCESS_NAMES, seed);
      parentName = i % 2 === 0 ? "explorer.exe" : "winword.exe";
      sha256 = sha256FromSeed(seed);
      path = pick(PATHS, seed);
      action = "execute";
      description = `${processName} executed on ${host} with suspicious command line; parent ${parentName}`;
    } else if (shape === 1) {
      // Network connection
      srcIp = pick(INTERNAL_IPS, seed);
      dstIp = pick(EXTERNAL_IPS, seed + 1);
      port = [443, 80, 8080, 4444, 53][seed % 5];
      action = i % 2 === 0 ? "network_send" : undefined;
      description = `Outbound connection from ${srcIp} to ${dstIp}:${port} on ${host}`;
    } else if (shape === 2) {
      // File write
      path = pick(PATHS, seed);
      sha256 = sha256FromSeed(seed + 7);
      action = "write";
      description = `Suspicious file written: ${path} on ${host}`;
    } else if (shape === 3) {
      // Logon / account
      const user = ["jdoe", "svc_sql", "administrator", "backup", "DOMAIN\\jsmith"][seed % 5];
      description = `Logon event for ${user} on ${host} from ${pick(INTERNAL_IPS, seed + 3)}`;
    } else {
      // Generic detection
      md5 = sha256FromSeed(seed + 99).slice(0, 32);
      description = `[${source}] Detection on ${host}: ${pick(TECHNIQUES, seed + 4)} activity observed`;
    }

    // Sprinkle some IOC references into descriptions so asset-graph / corroboration work.
    if (i % 7 === 0) {
      const ref = pick(state.iocs, seed + 5);
      description += ` related to ${ref.value}`;
    }

    const event: ForensicEvent = {
      id: `evt-${i.toString().padStart(5, "0")}`,
      timestamp: ts,
      description,
      severity,
      mitreTechniques: [technique],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: host,
      sources: [source],
      sha256,
      md5,
      path,
      processName,
      parentName,
      action,
      srcIp,
      dstIp,
      port,
    };
    state.forensicTimeline.push(event);
  }

  // Add a few findings so the report's findings section is exercised.
  for (let i = 0; i < 50; i++) {
    state.findings.push({
      id: `f-${i}`,
      severity: pickWeighted(SEVERITIES, SEV_WEIGHTS, i * 31),
      title: `Finding ${i}: ${pick(TECHNIQUES, i * 17)} on ${pick(HOSTS, i * 23)}`,
      description: `Synthesized finding for load test.`,
      relatedIocs: [`ioc-${i % TARGET_IOC_COUNT}`, `ioc-${(i + 1) % TARGET_IOC_COUNT}`],
      mitreTechniques: [pick(TECHNIQUES, i * 19)],
      sourceScreenshots: [],
      firstSeen: isoAtMinutes(start, i * 10),
      lastUpdated: isoAtMinutes(start, i * 10 + 5),
      status: "open",
    });
  }

  // Add a couple of key questions / next steps so report sections render.
  state.keyQuestions.push(
    { id: "q1", question: "What was the initial access vector?", status: "partial", answer: "Phishing suspected.", pointer: "evt-00000" },
    { id: "q2", question: "Was data exfiltrated?", status: "unknown", answer: "", pointer: "Check proxy logs" },
  );
  state.nextSteps.push(
    { id: "s1", priority: "critical", action: "Isolate WKSTN-03", rationale: "C2 beaconing observed", pointer: "evt-00010" },
  );
  state.attackerPath = "Initial access via phishing → execution of malicious macro → PowerShell payload → lateral movement via SMB → data staging.";
  state.lastSummary = "A multi-stage intrusion targeting the corporate workstation fleet; several hosts show beaconing and credential access activity.";
  state.updatedAt = isoAtMinutes(start, TARGET_EVENT_COUNT * 2);

  return state;
}

function timeMs(fn: () => void): { ms: number; result?: unknown } {
  const t0 = performance.now();
  const result = fn();
  const ms = performance.now() - t0;
  return { ms, result };
}

describe("load test — 10k synthetic events", { timeout: 60_000 }, () => {
  let state!: InvestigationState;
  beforeAll(() => { state = buildSyntheticState(); }, 60_000);

  it("generates the expected synthetic case size", () => {
    expect(state.forensicTimeline.length).toBe(TARGET_EVENT_COUNT);
    expect(state.iocs.length).toBe(TARGET_IOC_COUNT);
    expect(state.findings.length).toBe(50);
  });

  it("selectSynthesisEvents stays fast and stratifies the timeline", () => {
    const { ms, result } = timeMs(() => selectSynthesisEvents(state.forensicTimeline, 300));
    const selected = result as ForensicEvent[];
    expect(selected.length).toBeLessThanOrEqual(300);
    expect(selected.length).toBeGreaterThan(0);
    // Chronological order.
    for (let i = 1; i < selected.length; i++) {
      expect(selected[i].timestamp >= selected[i - 1].timestamp).toBe(true);
    }
    expect(ms).toBeLessThan(500); // linear sort on 10k; quadratic would be seconds
  });

  it("buildSynthesisContext stays fast and produces asset + verdict digest", () => {
    const scoped = state.forensicTimeline.slice(0, 300);
    const { ms, result } = timeMs(() => buildSynthesisContext(state, scoped));
    const ctx = result as string;
    expect(ctx.length).toBeGreaterThan(0);
    expect(ctx).toContain("COMPROMISED ASSETS");
    expect(ctx).toContain("THREAT-INTEL VERDICTS");
    expect(ms).toBeLessThan(500);
  });

  it("correlateEvents stays fast and is idempotent", () => {
    const { ms: ms1, result: r1 } = timeMs(() => correlateEvents(state.forensicTimeline, { windowSeconds: 2 }));
    const correlated = r1 as ForensicEvent[];
    expect(correlated.length).toBeGreaterThan(0);
    expect(correlated.length).toBeLessThanOrEqual(state.forensicTimeline.length);

    // Idempotency: second pass on already-correlated output must be stable.
    const { ms: ms2, result: r2 } = timeMs(() => correlateEvents(correlated, { windowSeconds: 2 }));
    const second = r2 as ForensicEvent[];
    expect(second.length).toBe(correlated.length);

    expect(ms1).toBeLessThan(2000); // hash/path union-find on 10k
    expect(ms2).toBeLessThan(500);  // idempotent re-run should be near-instant

    // Correctness: two events that share a sha256 within the window merge into one.
    const sharedHash = "a".repeat(64);
    const tA = "2026-06-15T00:00:00.000Z";
    const tB = new Date(new Date(tA).getTime() + 1000).toISOString();
    const pair: ForensicEvent[] = [
      { id: "c-a", timestamp: tA, description: "proc a", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sha256: sharedHash, sources: ["THOR"] },
      { id: "c-b", timestamp: tB, description: "proc b", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], sha256: sharedHash, sources: ["SIEM"] },
    ];
    expect(correlateEvents(pair, { windowSeconds: 2 }).length).toBe(1);
  });

  it("filterEventsByScope + applyLegitimate stay fast", () => {
    const scope = { start: "2026-06-15T06:00:00.000Z", end: "2026-06-15T18:00:00.000Z" };
    const markers: LegitimateMarker[] = [
      { id: "ioc:10.0.0.10", kind: "ioc", ref: "10.0.0.10", note: "test", markedAt: "2026-06-15T00:00:00Z" },
      { id: "event:evt-00000", kind: "event", ref: "evt-00000", note: "test", markedAt: "2026-06-15T00:00:00Z" },
    ];

    const { ms: msScope, result: rScope } = timeMs(() => filterEventsByScope(state.forensicTimeline, scope));
    const filtered = rScope as ForensicEvent[];
    // A 12-hour window over a ~250-hour timeline captures a fraction of events.
    expect(filtered.length).toBeGreaterThan(0);
    expect(filtered.length).toBeLessThan(state.forensicTimeline.length);
    expect(msScope).toBeLessThan(200);

    const { ms: msLegit, result: rLegit } = timeMs(() => applyLegitimate(state, markers));
    const legit = rLegit as InvestigationState;
    // The IOC marker for "10.0.0.10" removes matching IOCs from the returned state.
    expect(legit.iocs.length).toBeLessThan(state.iocs.length);
    expect(msLegit).toBeLessThan(200);
  });

  it("renderMarkdownReport stays fast", () => {
    const { ms, result } = timeMs(() => renderMarkdownReport(state, emptyReportMeta()));
    const report = result as string;

    expect(report.length).toBeGreaterThan(10_000);
    expect(report).toContain("## 4 Investigation");
    expect(report).toContain("### 3.1 Incident timeline");
    expect(report).toContain("### 4.2 Compromised assets");

    expect(ms).toBeLessThan(5000); // report renders all derived views on 10k events
  });
});
