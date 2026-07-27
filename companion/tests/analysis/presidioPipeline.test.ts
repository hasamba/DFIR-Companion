import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { PresidioPendingStore } from "../../src/analysis/presidioPending.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { buildStateSummary } from "../../src/analysis/summary.js";
import { PresidioApprovalRequired, type PresidioClient, type PresidioFinding } from "../../src/analysis/presidio.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import type { CustomEntity } from "../../src/analysis/anonymize.js";
import type { CaptureMetadata } from "../../src/types.js";
import type { Logger } from "../../src/logging/logger.js";

// End-to-end coverage of the Presidio gate GLUE in analyzeRestored (the chokepoint all 27 AI call
// sites funnel through). Presidio runs AFTER the local anonymizer on already-masked text, so this
// proves the pipeline (a) masks first, (b) throws + persists on an unseen value, (c) proceeds once
// approved, and (d) fails closed when the client itself errors. No socket is ever opened — the
// client is a stub injected via AnalysisPipelineOptions.presidio.

class StubProvider implements AIProvider {
  readonly name = "stub";
  readonly model = "stub-model";
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return {
      rawText: JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
        forensicEvents: [], timelineNote: "", summary: "",
      }),
    };
  }
}

function stubClient(findings: PresidioFinding[], seen: string[] = []): PresidioClient {
  return {
    analyze: async (text: string) => {
      seen.push(text);
      return findings;
    },
  };
}

function capture(): CaptureMetadata {
  return {
    caseId: "c1", sequenceNumber: 1, timestamp: "2026-05-28T10:01:00.000Z",
    url: "https://velociraptor.local", tabTitle: "VR", triggerType: "timer",
    contentHash: "0000000000000000", isDuplicate: false, screenshotFile: "000001_t.webp",
  };
}

// host defaults to a value the anonymizer will tokenize, so the masked-text assertion has
// something real to look for. `discoveredStoreOverride` lets a test substitute a fake store (e.g.
// one that returns non-lowercased `suppressed` values) instead of the real, always-lowercasing one.
async function makePipeline(
  client: PresidioClient,
  discovered: CustomEntity[] = [],
  host = "DC01.victim.local",
  discoveredStoreOverride?: DiscoveredEntitiesStore,
  // Test-only extras layered onto the pipeline's options — currently used only by the
  // truncation-warning test, which needs a tiny presidioScanCapsOverride and a logger it can
  // inspect. Optional and additive so every existing call site is unaffected.
  extraOptions: { presidioScanCapsOverride?: { chunkChars: number; maxChars: number }; logger?: Logger } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidiopipe-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  s.forensicTimeline = [{
    id: "e1", timestamp: "2026-01-01T00:00:00Z", description: `process run on ${host}`,
    severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: host,
  }];
  await stateStore.save(s);

  const discoveredStore = discoveredStoreOverride ?? new DiscoveredEntitiesStore(cases);
  if (!discoveredStoreOverride && discovered.length > 0) await discoveredStore.addDiscovered("c1", discovered);
  const presidioPendingStore = new PresidioPendingStore(cases);

  const pipeline = new AnalysisPipeline({
    provider: new StubProvider(),
    stateStore,
    anonStore: new AnonControlStore(cases), // anonymization defaults ON
    discoveredStore,
    presidioPendingStore,
    presidio: { client, url: "http://localhost:5002", minScore: 0.6 },
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/png" }),
    ...extraOptions,
  });
  return { pipeline, presidioPendingStore, discoveredStore, stateStore };
}

// A Logger stub that captures warn() calls verbatim (message text only — no console/file I/O),
// so a test can assert on the EXACT wording of a warning rather than just "something logged".
function capturingLogger(): { logger: Logger; warnings: string[] } {
  const warnings: string[] = [];
  const logger: Logger = {
    debug: () => {},
    info: () => {},
    warn: (message) => { warnings.push(message); },
    error: () => {},
    getLevel: () => "debug",
    setLevel: () => {},
    close: async () => {},
  };
  return { logger, warnings };
}

// A fake DiscoveredEntitiesStore that returns `suppressed` values EXACTLY as given — bypassing the
// real store's sanitizeDiscovered(), which always lower-cases them. Used to prove the gate itself
// case-folds `known.suppressed` rather than trusting the store to have done so already.
function fakeDiscoveredStore(suppressed: string[]): DiscoveredEntitiesStore {
  return {
    load: async () => ({ discovered: [], suppressed }),
    addDiscovered: async () => ({ discovered: [], suppressed }),
    suppress: async () => ({ discovered: [], suppressed }),
    unsuppress: async () => ({ discovered: [], suppressed }),
  } as unknown as DiscoveredEntitiesStore;
}

describe("analyzeRestored + Presidio", () => {
  it("throws PresidioApprovalRequired when a value is new to the case", async () => {
    const { pipeline } = await makePipeline(stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }]));
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toBeInstanceOf(PresidioApprovalRequired);
  });

  it("persists the pending findings so the dashboard can render them", async () => {
    const { pipeline, presidioPendingStore } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }]),
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(await presidioPendingStore.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("proceeds once the value is already in the discovered list", async () => {
    // `seen`/`presidioPendingStore` prove the gate actually RAN and cleared, not merely that the
    // call resolved — resolves.toBeDefined() alone passes even with the whole feature deleted,
    // since analyzeWindow resolves to state on the happy path regardless of Presidio.
    const seen: string[] = [];
    const { pipeline, presidioPendingStore } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }], seen),
      [{ value: "Jane Doe", category: "PERSON" }],
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).resolves.toBeDefined();
    expect(seen).toHaveLength(1);
    expect(await presidioPendingStore.load("c1")).toEqual([]);
  });

  it("does not gate on a suppressed value even if the store's case-folding invariant is violated", async () => {
    // known.suppressed is DOCUMENTED as pre-lowercased and the real store enforces it, but the
    // gate must not silently depend on that — a fake store here hands back "Jane Doe" (mixed
    // case) as the analyst's suppression veto, deliberately bypassing sanitizeDiscovered().
    const seen: string[] = [];
    const { pipeline } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }], seen),
      [],
      "DC01.victim.local",
      fakeDiscoveredStore(["Jane Doe"]),
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).resolves.toBeDefined();
    expect(seen).toHaveLength(1);
  });

  it("sends Presidio MASKED text, never raw values", async () => {
    const seen: string[] = [];
    const { pipeline } = await makePipeline(stubClient([], seen));
    await pipeline.analyzeWindow("c1", [capture()]);
    expect(seen).toHaveLength(1);
    expect(seen[0]).not.toContain("DC01.victim.local");
    expect(seen[0]).toMatch(/ANON_HOST_1/);
  });

  it("fails the AI call when the client throws", async () => {
    const dead: PresidioClient = { analyze: async () => { throw new Error("ECONNREFUSED"); } };
    const { pipeline } = await makePipeline(dead);
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toThrow(/not reachable/);
  });

  it("does not retry the approval gate", async () => {
    const seen: string[] = [];
    const { pipeline } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }], seen),
    );
    await expect(pipeline.analyzeWindow("c1", [capture()])).rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(seen).toHaveLength(1);
  });
});

// Three rows → three AI chunks at rowsPerBatch: 1. The payload stays far under the scan cap, so
// the pre-scan is exactly one /analyze request.
const THREE_ROW_CSV = [
  "timestamp,host,message",
  "2026-01-01T00:00:00Z,DC01.victim.local,logon by alice",
  "2026-01-01T00:01:00Z,DC01.victim.local,logon by bob",
  "2026-01-01T00:02:00Z,DC01.victim.local,logon by carol",
].join("\n");

function csvOpts() {
  return { label: "evidence.csv", idPrefix: "t1", importedAt: "2026-01-01T00:00:00Z", rowsPerBatch: 1 };
}

describe("presidio import pre-scan", () => {
  it("scans the whole payload once, not once per chunk", async () => {
    const seen: string[] = [];
    const { pipeline } = await makePipeline(stubClient([], seen));
    await pipeline.analyzeCsv("c1", THREE_ROW_CSV, csvOpts());
    expect(seen).toHaveLength(1);
  });

  it("scans MASKED text, so the known host never reaches Presidio", async () => {
    const seen: string[] = [];
    const { pipeline } = await makePipeline(stubClient([], seen));
    await pipeline.analyzeCsv("c1", THREE_ROW_CSV, csvOpts());
    expect(seen[0]).not.toContain("DC01.victim.local");
    expect(seen[0]).toMatch(/ANON_HOST_1/);
  });

  // The pre-scan used to receive only the CSV/log payload, but every batch prompt is
  // `buildStateSummary(state) + chunk` and every batch passes skipPresidioGate=true — so the
  // summary (findings, case summary, attacker path, all RESTORED to real values) went to the
  // provider having never been seen by Presidio. A fail-OPEN in a fail-closed layer.
  it("scans the state summary too, not just the payload", async () => {
    const seen: string[] = [];
    const { pipeline, stateStore } = await makePipeline(stubClient([], seen));
    const s = await stateStore.load("c1");
    s.findings = [{
      id: "f1", title: "SUMMARY_CANARY_VALUE exfiltrated data", description: "seen in the case",
      severity: "High", status: "open", relatedIocs: [], mitreTechniques: [], sourceScreenshots: [],
      firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z",
    }];
    await stateStore.save(s);

    await pipeline.analyzeCsv("c1", THREE_ROW_CSV, csvOpts());
    expect(seen).toHaveLength(1);
    expect(seen[0], "the state summary never reached Presidio").toContain("SUMMARY_CANARY_VALUE");
  });

  it("scans the state summary on log imports too", async () => {
    const seen: string[] = [];
    const { pipeline, stateStore } = await makePipeline(stubClient([], seen));
    const s = await stateStore.load("c1");
    s.findings = [{
      id: "f1", title: "SUMMARY_CANARY_VALUE exfiltrated data", description: "seen in the case",
      severity: "High", status: "open", relatedIocs: [], mitreTechniques: [], sourceScreenshots: [],
      firstSeen: "2026-01-01T00:00:00Z", lastUpdated: "2026-01-01T00:00:00Z",
    }];
    await stateStore.save(s);

    await pipeline.analyzeLog("c1", "Jan 1 00:00:00 sshd[1]: accepted publickey for svc", {
      label: "auth.log", idPrefix: "t3", importedAt: "2026-01-01T00:00:00Z",
    });
    expect(seen.length).toBeGreaterThanOrEqual(1);
    expect(seen[0], "the state summary never reached Presidio").toContain("SUMMARY_CANARY_VALUE");
  });

  it("rejects the whole import when the pre-scan finds a new value", async () => {
    const { pipeline, presidioPendingStore } = await makePipeline(
      stubClient([{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }]),
    );
    await expect(pipeline.analyzeCsv("c1", THREE_ROW_CSV, csvOpts()))
      .rejects.toBeInstanceOf(PresidioApprovalRequired);
    expect(await presidioPendingStore.load("c1")).toEqual([{ value: "Jane Doe", category: "PERSON" }]);
  });

  it("splits a payload larger than the chunk size into multiple requests", async () => {
    const seen: string[] = [];
    const { pipeline } = await makePipeline(stubClient([], seen));
    // Well over PRESIDIO_SCAN_CHUNK_CHARS (50_000) once the header is included.
    const bigCsv = ["timestamp,host,message"]
      .concat(Array.from({ length: 2000 }, (_, i) => `2026-01-01T00:00:00Z,DC01.victim.local,event ${i} padding padding`))
      .join("\n");
    await pipeline.analyzeCsv("c1", bigCsv, { ...csvOpts(), rowsPerBatch: 2000 });
    expect(seen.length).toBeGreaterThan(1);
    // Line-boundary splitting: no chunk may start mid-line.
    for (const chunk of seen.slice(1)) expect(chunk.startsWith("2026")).toBe(true);
  });

  // A silent partial scan is worse than no scan (#10 constraint): when the payload exceeds the
  // total-scan cap, the truncation must announce itself with the EXACT unscanned count. Real caps
  // are 50_000 / 5_000_000 characters — generating megabytes of synthetic text just to cross that
  // would be wasteful, so this test injects a tiny presidioScanCapsOverride via a real
  // AnalysisPipelineOptions field (production never sets it) instead.
  it("logs a warning naming the exact unscanned character count when the payload exceeds the cap", async () => {
    const { logger, warnings } = capturingLogger();
    const seen: string[] = [];
    const maxChars = 200;
    const chunkChars = 80;
    // An EMPTY host means the fixture event has no asset, so deriveKnownEntities finds nothing and
    // anon.apply() is a no-op on both halves of the scanned text — the filler rows below contain no
    // IP, account, email, card, phone or valid national ID either. masked.length is therefore
    // exactly the un-masked length, which makes "the correct unscanned count" independently
    // verifiable in the assertion below rather than merely re-deriving what the implementation did.
    const { pipeline, stateStore } = await makePipeline(
      stubClient([], seen),
      [],
      "",
      undefined,
      { presidioScanCapsOverride: { chunkChars, maxChars }, logger },
    );

    const header = "id,note";
    const rows = Array.from({ length: 40 }, (_, i) => `${i},filler data row ${i} more padding text here`);
    const csvText = [header, ...rows].join("\n");
    expect(csvText.length).toBeGreaterThan(maxChars); // sanity: this payload must actually cross the cap

    // The pre-scan covers the state summary as well as the payload (it is prepended to every batch
    // prompt), so the expected length is both halves, joined exactly as the pipeline joins them.
    const prefix = `${buildStateSummary(await stateStore.load("c1"))}\n`;

    await pipeline.analyzeCsv("c1", csvText, {
      label: "big.csv", idPrefix: "t2", importedAt: "2026-01-01T00:00:00Z", rowsPerBatch: 1000,
    });

    const expectedUnscanned = prefix.length + csvText.length - maxChars;
    const warning = warnings.find((w) => w.includes("pre-scan truncated"));
    expect(warning).toBeDefined();
    expect(warning).toContain(`${expectedUnscanned} character(s)`);
    expect(warning).toContain(`cap is ${maxChars} characters`);

    // The truncation is real, not just logged: what actually reached Presidio never exceeds the cap.
    const totalSent = seen.reduce((n, c) => n + c.length, 0);
    expect(totalSent).toBeLessThanOrEqual(maxChars);
  });
});
