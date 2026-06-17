import { describe, it, expect } from "vitest";
import {
  formatBytes,
  formatAge,
  buildAiDiagnostics,
  summarizeImportAttempts,
  countByKind,
  aggregateCaseSizes,
  buildDiagnosticsText,
  type AiError,
  type DiagnosticsReport,
} from "../../src/analysis/diagnostics.js";

describe("formatBytes", () => {
  it("formats sub-KB as bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
  });
  it("formats KB/MB/GB with one decimal under 100", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatBytes(2 * 1024 * 1024 * 1024)).toBe("2.0 GB");
  });
  it("drops the decimal at/over 100 units", () => {
    expect(formatBytes(150 * 1024)).toBe("150 KB");
  });
  it("returns an em dash for invalid input", () => {
    expect(formatBytes(NaN)).toBe("—");
    expect(formatBytes(-5)).toBe("—");
  });
});

describe("formatAge", () => {
  it("renders seconds / minutes / hours / days", () => {
    expect(formatAge(0)).toBe("0s");
    expect(formatAge(5_000)).toBe("5s");
    expect(formatAge(90_000)).toBe("1m");
    expect(formatAge(3 * 60 * 60 * 1000)).toBe("3h");
    expect(formatAge(2 * 24 * 60 * 60 * 1000)).toBe("2d");
  });
});

describe("buildAiDiagnostics", () => {
  it("reports not-configured for an empty env", () => {
    const d = buildAiDiagnostics({});
    expect(d.configured).toBe(false);
    expect(d.provider).toBeNull();
    expect(d.model).toBeNull();
    // sensible numeric defaults
    expect(d.timeoutMs).toBe(180_000);
    expect(d.maxTokens).toBe(16_000);
    expect(d.contextTokens).toBe(128_000);
    expect(d.anonymizeDefault).toBe(true);
  });

  it("reads provider/model/baseUrl and detects a local provider", () => {
    const d = buildAiDiagnostics({
      DFIR_AI_PROVIDER: "ollama",
      DFIR_AI_MODEL: "llama3",
      DFIR_AI_BASE_URL: "http://localhost:11434",
      DFIR_ANONYMIZE: "off",
    });
    expect(d.configured).toBe(true);
    expect(d.provider).toBe("ollama");
    expect(d.model).toBe("llama3");
    expect(d.local).toBe(true);
    expect(d.anonymizeDefault).toBe(false);
  });

  it("treats a cloud provider as non-local and falls synth model back to the main model", () => {
    const d = buildAiDiagnostics({ DFIR_AI_PROVIDER: "anthropic", DFIR_AI_MODEL: "claude" });
    expect(d.local).toBe(false);
    expect(d.synthModel).toBe("claude");
  });

  it("NEVER surfaces an API key, even if one is present in the env", () => {
    const d = buildAiDiagnostics({
      DFIR_AI_PROVIDER: "openai",
      DFIR_AI_MODEL: "gpt-4o",
      DFIR_AI_KEY: "sk-secret-should-never-leak",
    });
    const serialized = JSON.stringify(d);
    expect(serialized).not.toContain("sk-secret-should-never-leak");
    expect(Object.keys(d)).not.toContain("apiKey");
    expect(Object.keys(d)).not.toContain("key");
  });
});

describe("summarizeImportAttempts", () => {
  const now = 1_000 * 24 * 60 * 60 * 1000; // arbitrary fixed "now"
  const hour = 60 * 60 * 1000;
  const day = 24 * hour;

  it("buckets timestamps into 24h / 7d / total", () => {
    const ts = [
      now - hour, // within 24h
      now - 2 * hour, // within 24h
      now - 3 * day, // within 7d
      now - 10 * day, // older
    ];
    const s = summarizeImportAttempts(ts, now);
    expect(s.total).toBe(4);
    expect(s.last24h).toBe(2);
    expect(s.last7d).toBe(3);
  });

  it("ignores non-finite timestamps but keeps them in total", () => {
    const s = summarizeImportAttempts([now, NaN], now);
    expect(s.total).toBe(2);
    expect(s.last24h).toBe(1);
  });
});

describe("countByKind", () => {
  it("counts AI errors by classified kind", () => {
    const errs: AiError[] = [
      { at: "t1", caseId: "c", phase: "import", kind: "auth", detail: "" },
      { at: "t2", caseId: "c", phase: "import", kind: "auth", detail: "" },
      { at: "t3", caseId: "c", phase: "synth", kind: "billing", detail: "" },
    ];
    expect(countByKind(errs)).toEqual({ auth: 2, billing: 1 });
  });
  it("returns an empty object for no errors", () => {
    expect(countByKind([])).toEqual({});
  });
});

describe("aggregateCaseSizes", () => {
  it("totals bytes, sorts cases largest-first, and surfaces the top-N files", () => {
    const r = aggregateCaseSizes(
      [
        { caseId: "a", path: "x.webp", bytes: 100 },
        { caseId: "a", path: "y.webp", bytes: 50 },
        { caseId: "b", path: "z.json", bytes: 500 },
      ],
      2,
    );
    expect(r.totalBytes).toBe(650);
    expect(r.cases).toEqual([
      { caseId: "b", bytes: 500 },
      { caseId: "a", bytes: 150 },
    ]);
    expect(r.largestFiles).toEqual([
      { caseId: "b", path: "z.json", bytes: 500 },
      { caseId: "a", path: "x.webp", bytes: 100 },
    ]);
  });

  it("ignores invalid byte counts", () => {
    const r = aggregateCaseSizes([
      { caseId: "a", path: "ok", bytes: 10 },
      { caseId: "a", path: "bad", bytes: NaN },
      { caseId: "a", path: "neg", bytes: -5 },
    ]);
    expect(r.totalBytes).toBe(10);
    expect(r.largestFiles).toEqual([{ caseId: "a", path: "ok", bytes: 10 }]);
  });
});

function sampleReport(): DiagnosticsReport {
  return {
    generatedAt: "2026-06-17T00:00:00.000Z",
    uptimeMs: 3 * 60 * 60 * 1000,
    casesRoot: "/data/cases",
    disk: {
      totalBytes: 1024 * 1024 * 1024 * 1024,
      freeBytes: 512 * 1024 * 1024 * 1024,
      usedPct: 50,
      level: "none",
      thresholds: { warnPct: 70, dangerPct: 85, criticalPct: 95 },
    },
    cases: { count: 3, open: 2, closed: 1 },
    queue: { bufferedCaptures: 4, casesBuffering: 1, oldestBufferedAgeMs: 90_000, synthInFlight: 1, pendingAnalysisCases: 0 },
    ai: {
      configured: true,
      provider: "anthropic",
      model: "claude-x",
      synthModel: "claude-x",
      secondOpinionModel: null,
      velociraptorModel: null,
      baseUrl: null,
      imageDetail: "high",
      timeoutMs: 180000,
      maxTokens: 16000,
      contextTokens: 128000,
      anonymizeDefault: true,
      local: false,
      recentErrors: [],
      errorCounts: { billing: 1 },
    },
    importers: {
      attempts: { total: 12, last24h: 2, last7d: 9 },
      recentFailures: [
        { at: "2026-06-17T00:00:00.000Z", caseId: "case-1", kind: "siem", filename: "alerts.json", error: "bad JSON" },
      ],
      customImporters: 0,
    },
  };
}

describe("buildDiagnosticsText", () => {
  it("produces a human-readable, key-free blob", () => {
    const text = buildDiagnosticsText(sampleReport());
    expect(text).toContain("DFIR Companion — Diagnostics");
    expect(text).toContain("512 GB free of 1.0 TB");
    expect(text).toContain("3 total (2 open, 1 closed)");
    expect(text).toContain("provider: anthropic (external)");
    expect(text).toContain("recent AI errors: billing=1");
    expect(text).toContain("attempts: 2 (24h) · 9 (7d) · 12 total");
    expect(text).toContain("case-1 siem alerts.json: bad JSON");
  });

  it("renders the not-configured AI case", () => {
    const r = sampleReport();
    r.ai = { ...r.ai, configured: false, errorCounts: {} };
    const text = buildDiagnosticsText(r);
    expect(text).toContain("not configured");
    expect(text).not.toContain("provider: anthropic");
  });
});
