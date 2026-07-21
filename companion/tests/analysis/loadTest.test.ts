import { describe, it, expect, beforeAll } from "vitest";
import { emptyState, type ForensicEvent, type IOC, type InvestigationState, type Severity } from "../../src/analysis/stateTypes.js";
import { selectSynthesisEvents, buildSynthesisContext } from "../../src/analysis/synthSelect.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import { filterEventsByScope } from "../../src/analysis/scope.js";
import { applyFalsePositive, type FalsePositiveMarker } from "../../src/analysis/falsePositive.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";

// Performance / load test for issue #183: a synthetic 10k-event case exercising the hot
// deterministic paths. No AI calls, no I/O, no network — pure in-memory benchmarking.
//
// These tests assert almost no absolute wall-clock budget. Under a full parallel
// `vitest run` every worker competes for the same cores, and the same unchanged code
// measures 2-3x slower than it does in isolation — so an absolute threshold either flakes
// (renderMarkdownReport: ~3.5s alone, 5.5s contended, against a 5s budget) or is loosened
// until it can no longer catch anything. Instead each hot path is timed against ITSELF at
// two input sizes: contention inflates both measurements, so the growth RATIO stays stable
// while still separating linear growth from a quadratic regression. See expectSubQuadratic.
//
// Grow ONE dimension at a time. Scaling events, IOCs and findings together makes a path
// that is merely linear in (events x iocs) look quadratic in events — renderMarkdownReport
// measured a bogus 7.8x-per-4x that way, and a clean 7.1x-per-8x once only the timeline
// grew. So every measurement below holds every dimension fixed except the one it varies.

const TARGET_EVENT_COUNT = 10_000;
const TARGET_IOC_COUNT = 500;
const FINDING_COUNT = 50;

// The baseline case is an eighth of the full one along whichever single dimension is under
// test. The bigger the gap, the wider the separation between acceptable and quadratic
// growth: at 8x input, linear costs 8x and quadratic costs 64x — room on both sides.
const GROWTH_FACTOR = 8;
const BASELINE_EVENT_COUNT = TARGET_EVENT_COUNT / GROWTH_FACTOR;
const BASELINE_IOC_COUNT = Math.round(TARGET_IOC_COUNT / GROWTH_FACTOR);

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

function buildSyntheticState(eventCount: number, iocCount: number): InvestigationState {
  const state = emptyState(`load-test-${eventCount}`);
  const start = new Date("2026-06-15T00:00:00.000Z");

  // IOCs first so events can reference them.
  for (let i = 0; i < iocCount; i++) {
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

  for (let i = 0; i < eventCount; i++) {
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

  // Add a few findings so the report's findings section is exercised. Fixed, not scaled:
  // findings are a separate dimension and must stay constant while events or IOCs grow.
  for (let i = 0; i < FINDING_COUNT; i++) {
    state.findings.push({
      id: `f-${i}`,
      severity: pickWeighted(SEVERITIES, SEV_WEIGHTS, i * 31),
      title: `Finding ${i}: ${pick(TECHNIQUES, i * 17)} on ${pick(HOSTS, i * 23)}`,
      description: `Synthesized finding for load test.`,
      relatedIocs: [`ioc-${i % iocCount}`, `ioc-${(i + 1) % iocCount}`],
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
  state.updatedAt = isoAtMinutes(start, eventCount * 2);

  return state;
}

interface Measurement { ms: number; result: unknown }

// Best of N runs. Contention and GC can only ever ADD time, so the minimum is the closest
// estimate of the code's own cost and — unlike a single sample — one scheduler stall can't
// skew it.
function bestOf(fn: () => unknown, repeats: number): Measurement {
  let ms = Infinity;
  let result: unknown;
  for (let i = 0; i < repeats; i++) {
    const t0 = performance.now();
    result = fn();
    const elapsed = performance.now() - t0;
    if (elapsed < ms) ms = elapsed;
  }
  return { ms, result };
}

// How much slower the same code may get when its input grows GROWTH_FACTOR (8x) along one
// dimension. Linear work costs 8x; a quadratic regression costs 64x. Measured today:
// renderMarkdownReport 7.1x and filterEventsByScope ~8x (linear), buildSynthesisContext
// 3.7-7.7x in IOC count (linear), correlateEvents 12.8-14.4x (~n^1.25, sort + windowed
// scan). 32 leaves 2x of headroom over the slowest of those and sits 2x below quadratic.
const GROWTH_LIMIT = 32;
// Absolute slack, so a sub-millisecond baseline (where timer resolution dominates and the
// ratio is meaningless) can't fail the assertion on noise alone. Any genuinely quadratic
// path costs far more than this at 10k events, so it does not blunt the check.
const FLOOR_MS = 25;

interface Growth { baseline: Measurement; full: Measurement; label: string; dimension: string }

// Measures one hot path at both input sizes. The full-size run happens FIRST as a discarded
// warmup: V8 needs a few thousand iterations of the inner loops before it settles on
// optimized code, and without this the baseline (measured first) absorbs the whole JIT cost
// — enough to make a cheap path look like it got *faster* on 8x the input.
function measureGrowth(
  label: string,
  dimension: string,
  baselineFn: () => unknown,
  fullFn: () => unknown,
  repeats: number,
): Growth {
  fullFn();
  const baseline = bestOf(baselineFn, repeats);
  const full = bestOf(fullFn, repeats);
  return { baseline, full, label, dimension };
}

// Asserts the growth ratio, and returns the full-size result so the caller can assert on it.
function expectSubQuadratic(measured: Growth): unknown {
  const { baseline, full, label, dimension } = measured;
  const limit = baseline.ms * GROWTH_LIMIT + FLOOR_MS;
  const growth = baseline.ms > 0 ? `${(full.ms / baseline.ms).toFixed(1)}x` : "n/a";
  const detail =
    `${label} (${dimension}): ${baseline.ms.toFixed(1)}ms → ${full.ms.toFixed(1)}ms ` +
    `(${growth} for ${GROWTH_FACTOR}x input)`;
  // Logged unconditionally so a slow-but-passing trend is still visible in the run output.
  console.log(`[load] ${detail}`);
  expect(full.ms, `${detail} — expected under ${limit.toFixed(1)}ms; growth this steep means the path went super-linear`)
    .toBeLessThan(limit);
  return full.result;
}

describe("load test — 10k synthetic events", { timeout: 120_000 }, () => {
  let state!: InvestigationState;       // full case: 10k events / 500 IOCs / 50 findings
  let fewerEvents!: InvestigationState; // same case with an eighth of the TIMELINE
  let fewerIocs!: InvestigationState;   // same case with an eighth of the IOCS
  beforeAll(() => {
    state = buildSyntheticState(TARGET_EVENT_COUNT, TARGET_IOC_COUNT);
    fewerEvents = buildSyntheticState(BASELINE_EVENT_COUNT, TARGET_IOC_COUNT);
    // Same timeline, fewer IOCs — derived immutably rather than regenerated so the events
    // are byte-identical and the IOC count is genuinely the only thing that changed.
    fewerIocs = { ...state, iocs: state.iocs.slice(0, BASELINE_IOC_COUNT) };
  }, 120_000);

  it("generates the expected synthetic case size", () => {
    expect(state.forensicTimeline.length).toBe(TARGET_EVENT_COUNT);
    expect(state.iocs.length).toBe(TARGET_IOC_COUNT);
    expect(state.findings.length).toBe(FINDING_COUNT);
    // Each baseline varies exactly one dimension.
    expect(fewerEvents.forensicTimeline.length).toBe(BASELINE_EVENT_COUNT);
    expect(fewerEvents.iocs.length).toBe(TARGET_IOC_COUNT);
    expect(fewerIocs.forensicTimeline.length).toBe(TARGET_EVENT_COUNT);
    expect(fewerIocs.iocs.length).toBe(BASELINE_IOC_COUNT);
  });

  it("selectSynthesisEvents stays bounded and stratifies the timeline", () => {
    // The one path here that gets an absolute ceiling rather than a growth ratio, because its
    // cost is still not monotonic in the timeline length — though only mildly, and for a
    // structural reason rather than an algorithmic one. A timeline whose Critical/High rows
    // outnumber the budget short-circuits into the severity-trim branch and skips the reserved
    // fills entirely, so two sizes either side of that threshold run DIFFERENT code and a ratio
    // between them compares nothing meaningful. On this synthetic data (~10% Critical/High, so
    // the threshold falls between 2500 and 3000 events) the whole 1250→10000 range now costs
    // single-digit milliseconds, varying by a factor of ~2 with no cliff anywhere in it.
    //
    // The much larger swing this comment used to record (~29ms at 1250, ~100ms at 2500 — a 20x
    // inversion against 5000) was a genuine defect, not a property of the algorithm: the
    // anchor-context fill re-scanned the whole timeline once per anchor. That is fixed, and
    // synthSelect.test.ts now guards the complexity directly, holding the timeline constant and
    // varying only the anchor count so no threshold sits between the two measurements.
    // The ceiling below stays deliberately loose — contention cannot reach it, while a
    // reintroduced quadratic on 10k events (seconds at least) still would.
    const measured = bestOf(() => selectSynthesisEvents(state.forensicTimeline, 300), 5);
    console.log(`[load] selectSynthesisEvents (${TARGET_EVENT_COUNT} events): ${measured.ms.toFixed(1)}ms`);
    expect(measured.ms, `selectSynthesisEvents took ${measured.ms.toFixed(1)}ms on ${TARGET_EVENT_COUNT} events`)
      .toBeLessThan(2000);

    const selected = measured.result as ForensicEvent[];
    expect(selected.length).toBeLessThanOrEqual(300);
    expect(selected.length).toBeGreaterThan(0);
    // Chronological order.
    for (let i = 1; i < selected.length; i++) {
      expect(selected[i].timestamp >= selected[i - 1].timestamp).toBe(true);
    }
  });

  it("buildSynthesisContext scales sub-quadratically in IOC count and digests assets + verdicts", () => {
    // Cost is driven by the IOC set and the scoped slice, not the timeline length — synthesis
    // always passes a bounded slice (selectSynthesisEvents caps it at 300). So the dimension
    // that can actually run away on a real case is the IOC count, and that's what grows here.
    const scope = state.forensicTimeline.slice(0, 300);
    const measured = measureGrowth(
      "buildSynthesisContext",
      `${BASELINE_IOC_COUNT}→${TARGET_IOC_COUNT} IOCs`,
      () => buildSynthesisContext(fewerIocs, scope),
      () => buildSynthesisContext(state, scope),
      5,
    );

    const ctx = expectSubQuadratic(measured) as string;
    expect(ctx.length).toBeGreaterThan(0);
    expect(ctx).toContain("COMPROMISED ASSETS");
    expect(ctx).toContain("THREAT-INTEL VERDICTS");
  });

  it("correlateEvents scales sub-quadratically and is idempotent", () => {
    // The hash/path union-find is the most regression-prone path here — see #125, where an
    // O(n²) dedup in mergeDelta pegged a CPU for over an hour on a large import.
    const measured = measureGrowth(
      "correlateEvents",
      `${BASELINE_EVENT_COUNT}→${TARGET_EVENT_COUNT} events`,
      () => correlateEvents(fewerEvents.forensicTimeline, { windowSeconds: 2 }),
      () => correlateEvents(state.forensicTimeline, { windowSeconds: 2 }),
      3,
    );

    const correlated = expectSubQuadratic(measured) as ForensicEvent[];
    expect(correlated.length).toBeGreaterThan(0);
    expect(correlated.length).toBeLessThanOrEqual(state.forensicTimeline.length);

    // Idempotency: second pass on already-correlated output must be stable.
    const second = correlateEvents(correlated, { windowSeconds: 2 });
    expect(second.length).toBe(correlated.length);

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

  it("filterEventsByScope + applyFalsePositive scale sub-quadratically", () => {
    const scope = { start: "2026-06-15T06:00:00.000Z", end: "2026-06-15T18:00:00.000Z" };
    const markers: FalsePositiveMarker[] = [
      { id: "ioc:10.0.0.10", kind: "ioc", ref: "10.0.0.10", reason: "other", note: "test", markedAt: "2026-06-15T00:00:00Z", markedBy: "anonymous" },
      { id: "event:evt-00000", kind: "event", ref: "evt-00000", reason: "other", note: "test", markedAt: "2026-06-15T00:00:00Z", markedBy: "anonymous" },
    ];

    const scopeMeasured = measureGrowth(
      "filterEventsByScope",
      `${BASELINE_EVENT_COUNT}→${TARGET_EVENT_COUNT} events`,
      () => filterEventsByScope(fewerEvents.forensicTimeline, scope),
      () => filterEventsByScope(state.forensicTimeline, scope),
      5,
    );
    const filtered = expectSubQuadratic(scopeMeasured) as ForensicEvent[];
    // A 12-hour window over a ~250-hour timeline captures a fraction of events.
    expect(filtered.length).toBeGreaterThan(0);
    expect(filtered.length).toBeLessThan(state.forensicTimeline.length);

    const fpMeasured = measureGrowth(
      "applyFalsePositive",
      `${BASELINE_EVENT_COUNT}→${TARGET_EVENT_COUNT} events`,
      () => applyFalsePositive(fewerEvents, markers),
      () => applyFalsePositive(state, markers),
      5,
    );
    const fp = expectSubQuadratic(fpMeasured) as InvestigationState;
    // The IOC marker for "10.0.0.10" removes matching IOCs from the returned state.
    expect(fp.iocs.length).toBeLessThan(state.iocs.length);
  });

  it("renderMarkdownReport scales sub-quadratically", () => {
    const meta = emptyReportMeta();
    // The report renders every derived view (asset graph, timeline, IOC tables), so it is
    // the widest net for a regression in any one of them.
    const measured = measureGrowth(
      "renderMarkdownReport",
      `${BASELINE_EVENT_COUNT}→${TARGET_EVENT_COUNT} events`,
      () => renderMarkdownReport(fewerEvents, meta),
      () => renderMarkdownReport(state, meta),
      // Single measured run each (plus the warmup) — this is by far the most expensive path
      // in the file, and at ~8x growth against a 32x limit there is 4x of headroom, so it
      // does not need extra samples to absorb a scheduler stall.
      1,
    );
    const report = expectSubQuadratic(measured) as string;

    expect(report.length).toBeGreaterThan(10_000);
    expect(report).toContain("## 4 Investigation");
    expect(report).toContain("### 3.1 Incident timeline");
    expect(report).toContain("### 4.2 Compromised assets");
  });
});
