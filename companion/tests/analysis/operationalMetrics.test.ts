import { access, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import express from "express";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { Job } from "../../src/analysis/jobRegistry.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";
import type { CaptureMetadata } from "../../src/types.js";
import {
  OperationalMetricsStore,
  parseOperationalMetric,
  safeImporterLabel,
} from "../../src/analysis/operationalMetrics.js";
import { summarizeOperationalMetrics } from "../../src/analysis/operationalDiagnostics.js";
import { buildSupportBundle } from "../../src/analysis/supportBundle.js";
import { estimateImportRows, observeImport } from "../../src/analysis/operationalImport.js";
import {
  createOperationalHttpMetrics,
  exportFormatForPath,
} from "../../src/analysis/operationalHttpMetrics.js";
import { sampleOperationalCapacity } from "../../src/analysis/operationalCapacity.js";

describe("OperationalMetricsStore", () => {
  it("keeps only samples inside both retention bounds", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-operational-metrics-"));
    const path = join(root, "metrics.json");
    let now = Date.parse("2026-07-01T00:00:00.000Z");
    const store = new OperationalMetricsStore(path, {
      maxSamples: 3,
      retentionMs: 1_000,
      now: () => now,
    });

    for (let i = 0; i < 4; i++) {
      await store.record({
        type: "query",
        operation: "forensic_timeline",
        index: "timestamp",
        durationMs: i + 1,
        rows: i,
      });
      now += 100;
    }

    expect(
      (await store.snapshot()).filter((sample) => sample.type === "query").map((sample) => sample.durationMs),
    ).toEqual([2, 3, 4]);
    now += 2_000;
    expect(await store.snapshot()).toEqual([]);
    expect(JSON.parse(await readFile(path, "utf8")).samples).toHaveLength(3);
  });

  it("does not create a metrics file when disabled", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-operational-metrics-off-"));
    const path = join(root, "metrics.json");
    const store = new OperationalMetricsStore(path, { enabled: false });

    await store.record({
      type: "websocket",
      event: "connect",
      durationMs: 0,
    });

    await expect(access(path)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await store.snapshot()).toEqual([]);
  });
});

describe("StateStore operational metrics", () => {
  it("records query latency, row count and the selected safe index", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-query-metrics-"));
    const cases = new CaseStore(root);
    await cases.createCase({
      caseId: "case-secret",
      name: "Victim Name",
      investigator: "analyst",
      aiProvider: null,
    });
    const metrics = new OperationalMetricsStore(join(root, "metrics", "operational.json"));
    const stateStore = new StateStore(cases, undefined, { operationalMetrics: metrics });
    const event: ForensicEvent = {
      id: "e1",
      timestamp: "2026-07-01T00:00:00.000Z",
      description: "secret evidence description",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WIN-SECRET",
      sources: ["secret-source"],
    };
    await stateStore.save({ ...emptyState("case-secret"), forensicTimeline: [event] });

    await stateStore.queryForensicTimeline("case-secret", { host: "WIN-SECRET", limit: 10 });

    const samples = await metrics.snapshot();
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "query",
        operation: "forensic_timeline",
        index: "host",
        rows: 1,
      }),
    );
    expect(JSON.stringify(samples)).not.toContain("WIN-SECRET");
    expect(JSON.stringify(samples)).not.toContain("case-secret");
    expect(JSON.stringify(samples)).not.toContain("secret evidence description");
  });

  it("samples aggregate database, disk and process capacity without case labels", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-capacity-metrics-"));
    const cases = new CaseStore(root);
    await cases.createCase({
      caseId: "private-case",
      name: "Private",
      investigator: "Private",
      aiProvider: null,
    });
    const stateStore = new StateStore(cases);
    await stateStore.save(emptyState("private-case"));
    const metrics = new OperationalMetricsStore(join(root, "metrics", "operational.json"));

    await sampleOperationalCapacity(cases, stateStore, metrics);

    const samples = await metrics.snapshot();
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "capacity",
        databaseBytes: expect.any(Number),
        diskTotalBytes: expect.any(Number),
        rssBytes: expect.any(Number),
      }),
    );
    expect(JSON.stringify(samples)).not.toContain("private-case");
  });

  it("records indexed super-timeline query latency without retaining filter values", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-super-query-metrics-"));
    const cases = new CaseStore(root);
    await cases.createCase({
      caseId: "secret-case",
      name: "Secret",
      investigator: "Secret",
      aiProvider: null,
    });
    const metrics = new OperationalMetricsStore(join(root, "metrics.json"));
    const superTimeline = new SuperTimelineStore(cases, 100, metrics);
    await superTimeline.append("secret-case", [
      {
        id: "e1",
        timestamp: "2026-07-01T00:00:00.000Z",
        description: "secret evidence",
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "SECRET-HOST",
      },
    ]);

    await superTimeline.queryIndexed("secret-case", { host: "SECRET-HOST", limit: 10 });

    const samples = await metrics.snapshot();
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "query",
        operation: "super_timeline",
        index: "host",
        rows: 1,
      }),
    );
    expect(JSON.stringify(samples)).not.toContain("SECRET-HOST");
    expect(JSON.stringify(samples)).not.toContain("secret-case");
  });
});

describe("operational metric privacy", () => {
  it("maps unknown importer names to one fixed label", () => {
    expect(safeImporterLabel("siem")).toBe("siem");
    expect(safeImporterLabel("WIN-DC01.corp.local")).toBe("custom");
  });

  it("rejects unallowlisted label values at the persistence boundary", () => {
    expect(
      parseOperationalMetric({
        type: "query",
        at: "2026-07-01T00:00:00.000Z",
        operation: "customer-case-title",
        index: "none",
        durationMs: 1,
        rows: 1,
      }).success,
    ).toBe(false);
  });
});

describe("operational emitters", () => {
  it("counts common import containers without retaining their content", () => {
    expect(estimateImportRows('[{"secret":1},{"secret":2}]')).toBe(2);
    expect(estimateImportRows('{"rows":[{"x":1},{"x":2},{"x":3}]}')).toBe(3);
    expect(estimateImportRows("first secret\nsecond secret\n")).toBe(2);
  });

  it("records only a safe importer label and aggregate yield", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-import-metrics-"));
    const metrics = new OperationalMetricsStore(join(root, "metrics.json"));
    const state = {
      ...emptyState("secret-case"),
      forensicTimeline: [
        {
          id: "7e1",
          timestamp: "2026-07-01T00:00:00.000Z",
          description: "secret",
          severity: "High" as const,
          mitreTechniques: [],
          relatedFindingIds: [],
          sourceScreenshots: [],
        },
      ],
    };

    await observeImport(
      metrics,
      {
        kind: "customer-secret-importer",
        idPrefix: "7",
        text: "one\ntwo\nthree",
        startedAt: Date.now(),
      },
      Promise.resolve(state),
    );

    const samples = await metrics.snapshot();
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "import",
        importer: "custom",
        rowsRead: 3,
        accepted: 1,
        rejected: 2,
      }),
    );
    expect(JSON.stringify(samples)).not.toContain("customer-secret-importer");
    expect(JSON.stringify(samples)).not.toContain("secret-case");
  });

  it("maps export paths to fixed format labels", () => {
    expect(exportFormatForPath("/cases/case-secret/report.docx")).toBe("docx");
    expect(exportFormatForPath("/cases/case-secret/timeline.jsonl")).toBe("jsonl");
    expect(exportFormatForPath("/cases/case-secret/state")).toBeNull();
  });

  it("records aggregate export duration and size without retaining the request path", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-export-metrics-"));
    const metrics = new OperationalMetricsStore(join(root, "metrics.json"));
    const app = express();
    app.use(createOperationalHttpMetrics(metrics));
    app.get("/cases/customer-secret/report.docx", (_req, res) => res.send(Buffer.from("report")));

    await request(app).get("/cases/customer-secret/report.docx").expect(200);

    const samples = await metrics.snapshot();
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "export",
        format: "docx",
        outputBytes: 6,
        success: true,
      }),
    );
    expect(JSON.stringify(samples)).not.toContain("customer-secret");
  });

  it("records AI latency, retries, tokens and rate limits with fixed labels", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ai-metrics-"));
    const cases = new CaseStore(root);
    await cases.createCase({
      caseId: "secret-case",
      name: "Secret",
      investigator: "Secret",
      aiProvider: "mock",
    });
    const metrics = new OperationalMetricsStore(join(root, "metrics.json"));
    let attempts = 0;
    const provider: AIProvider = {
      name: "customer-secret-provider",
      model: "customer-secret-model",
      async analyze() {
        attempts += 1;
        if (attempts === 1) throw new ProviderError("customer secret transport detail", "transport");
        return {
          rawText: JSON.stringify({
            findings: [],
            iocs: [],
            mitreTechniques: [],
            threadsOpened: [],
            threadsClosed: [],
            timelineNote: "",
            summary: "complete",
          }),
          usage: { inputTokens: 120, outputTokens: 30, costUSD: 0.02 },
        };
      },
    };
    const pipeline = new AnalysisPipeline({
      provider,
      stateStore: new StateStore(cases),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      operationalMetrics: metrics,
      retries: 1,
      backoffMs: 0,
    });
    const capture: CaptureMetadata = {
      caseId: "secret-case",
      sequenceNumber: 1,
      timestamp: "2026-07-01T00:00:00.000Z",
      url: "https://secret.invalid",
      tabTitle: "Secret",
      triggerType: "timer",
      contentHash: "0000000000000000",
      isDuplicate: false,
      screenshotFile: "secret.webp",
    };

    await pipeline.analyzeWindow("secret-case", [capture]);

    const rateLimited = new AnalysisPipeline({
      provider: {
        name: "secret-rate-limit-provider",
        model: "secret-model",
        analyze: async () => {
          throw new ProviderError("secret quota detail", "rate_limit");
        },
      },
      stateStore: new StateStore(cases),
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      operationalMetrics: metrics,
      retries: 0,
    });
    await expect(rateLimited.analyzeWindow("secret-case", [capture])).rejects.toThrow("secret quota detail");

    const samples = await metrics.snapshot();
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "ai_retry",
        phase: "vision",
        errorKind: "transport",
      }),
    );
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "ai",
        phase: "vision",
        success: true,
        inputTokens: 120,
        outputTokens: 30,
        costUsd: 0.02,
      }),
    );
    expect(samples).toContainEqual(
      expect.objectContaining({
        type: "ai",
        phase: "vision",
        success: false,
        errorKind: "rate_limit",
      }),
    );
    const serialized = JSON.stringify(samples);
    expect(serialized).not.toContain("customer-secret-provider");
    expect(serialized).not.toContain("customer secret rate-limit detail");
    expect(serialized).not.toContain("secret-case");
  });
});

describe("summarizeOperationalMetrics", () => {
  it("identifies slow work, stalled jobs and projected disk pressure with remediation", () => {
    const now = Date.parse("2026-07-02T00:00:00.000Z");
    const samples = [
      {
        type: "import" as const,
        at: "2026-07-01T00:00:00.000Z",
        importer: "siem" as const,
        durationMs: 900,
        rowsRead: 100,
        accepted: 20,
        rejected: 80,
        promoted: 3,
        rejectionReason: "filtered" as const,
      },
      {
        type: "import" as const,
        at: "2026-07-01T00:01:00.000Z",
        importer: "kape" as const,
        durationMs: 100,
        rowsRead: 100,
        accepted: 90,
        rejected: 10,
        promoted: 0,
        rejectionReason: "filtered" as const,
      },
      {
        type: "query" as const,
        at: "2026-07-01T00:02:00.000Z",
        operation: "forensic_timeline" as const,
        index: "none" as const,
        durationMs: 700,
        rows: 500,
      },
      {
        type: "websocket" as const,
        at: "2026-07-01T00:03:00.000Z",
        event: "connect" as const,
        durationMs: 0,
      },
      {
        type: "websocket" as const,
        at: "2026-07-01T00:04:00.000Z",
        event: "reconnect" as const,
        durationMs: 0,
      },
      {
        type: "websocket" as const,
        at: "2026-07-01T00:05:00.000Z",
        event: "reap" as const,
        durationMs: 0,
      },
      {
        type: "capacity" as const,
        at: "2026-07-01T00:00:00.000Z",
        databaseBytes: 1_000,
        diskFreeBytes: 2_000,
        diskTotalBytes: 10_000,
        rssBytes: 500,
        heapUsedBytes: 200,
      },
      {
        type: "capacity" as const,
        at: "2026-07-02T00:00:00.000Z",
        databaseBytes: 2_000,
        diskFreeBytes: 1_000,
        diskTotalBytes: 10_000,
        rssBytes: 600,
        heapUsedBytes: 250,
      },
    ];
    const jobs: Job[] = [
      {
        id: "job-1",
        caseId: null,
        kind: "import",
        status: "running",
        priority: "normal",
        queuedAt: "2026-07-01T23:40:00.000Z",
        startedAt: "2026-07-01T23:41:00.000Z",
        updatedAt: "2026-07-01T23:42:00.000Z",
        warnings: [],
        attempt: 2,
        maxRetries: 2,
        resumable: true,
        cancellable: true,
      },
    ];

    const summary = summarizeOperationalMetrics(samples, jobs, now);

    expect(summary.slowest.importer?.name).toBe("siem");
    expect(summary.slowest.query?.name).toBe("forensic_timeline");
    expect(summary.slowest.job?.name).toBe("import");
    expect(summary.jobs.stalled).toBe(1);
    expect(summary.jobs.retries).toBe(1);
    expect(summary.websocket.reconnects).toBe(1);
    expect(summary.websocket.dropped).toBe(1);
    expect(summary.capacity.projectedDaysRemaining).toBeCloseTo(1);
    expect(summary.warnings.join(" ")).toContain("disk");
    expect(summary.slowest.query?.remediation).toContain("indexed");
  });
});

describe("buildSupportBundle", () => {
  it("contains aggregate health but excludes evidence, identifiers, paths and secrets", () => {
    const support = buildSupportBundle({
      generatedAt: "2026-07-02T00:00:00.000Z",
      version: "0.35.0",
      uptimeMs: 1_000,
      disk: { totalBytes: 10_000, freeBytes: 4_000, usedPct: 60, level: "none" },
      cases: { count: 2, open: 1, closed: 1, archived: 0 },
      queue: { queued: 1, running: 1, stalled: 0 },
      ai: {
        configured: true,
        local: false,
        errorsByKind: { rate_limit: 2, "customer-secret-error": 3 },
      },
      operational: null,
    });
    const serialized = JSON.stringify(support);

    expect(support.redactions.caseEvidence).toBe("excluded");
    expect(support.redactions.caseIdentifiers).toBe("excluded");
    expect(serialized).not.toContain('"caseId":');
    expect(serialized).not.toContain('"filename":');
    expect(serialized).not.toContain('"apiKey":');
    expect(serialized).not.toContain('"casesRoot":');
    expect(serialized).not.toContain("customer-secret-error");
  });
});
