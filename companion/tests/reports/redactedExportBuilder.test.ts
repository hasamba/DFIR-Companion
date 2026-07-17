import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { buildRedactedExport, type RedactedExportDeps } from "../../src/reports/redactedExportBuilder.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { DEFAULT_REDACTED_EXPORT_OPTIONS } from "../../src/analysis/redactedExport.js";
import type { ScreenshotRedactResult } from "../../src/analysis/imageRedact.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

// Minimal investigation state — one internal host so deriveKnownEntities has something to anonymize.
function fakeState(): InvestigationState {
  return {
    summary: "",
    forensicTimeline: [
      { eventId: "e1", timestamp: "2026-01-01T00:00:00Z", description: "VICTIM-PC ran 10.0.0.5", severity: "High", asset: "VICTIM-PC" },
    ],
    findings: [],
    iocs: [],
    mitreTechniques: [],
    attackerPath: [],
    keyQuestions: [],
    threads: [],
  } as unknown as InvestigationState;
}

// Stub deps: no real fs, sharp, or tesseract — the report contents and the image redactor are faked
// so the builder logic (anonymizer assembly, entry layout, summary) is exercised in isolation.
function deps(overrides: Partial<RedactedExportDeps> = {}): RedactedExportDeps {
  return {
    store: {} as RedactedExportDeps["store"],
    stateStore: { load: async () => fakeState() } as unknown as RedactedExportDeps["stateStore"],
    customEntities: { load: async () => [] } as unknown as RedactedExportDeps["customEntities"],
    discoveredEntities: { load: async () => ({ discovered: [], suppressed: [] }) } as unknown as RedactedExportDeps["discoveredEntities"],
    ocrRunner: { recognize: async () => [] },
    reportWriter: {
      // Echo back which redactions the anonymizer applies so the test can assert tokenization ran.
      redactedReportContents: async (_caseId: string, redact: (s: string) => string) => ({
        markdown: redact("VICTIM-PC at 10.0.0.5"),
        html: "<h1>r</h1>",
        findingsCsv: "f",
        iocsCsv: "i",
        timelineCsv: "t",
        forensicTimelineCsv: "ft",
        stateJson: "{}",
      }),
    },
    listScreenshots: async () => ["shot-001.png", "shot-002.png", "notes.txt"].filter((f) => /\.png$/.test(f)),
    readScreenshot: async (_id: string, file: string) => Buffer.from(`raw-${file}`),
    redactImage: async (buf: Buffer): Promise<ScreenshotRedactResult> => ({
      buffer: Buffer.concat([Buffer.from("REDACTED:"), buf]),
      blurred: true,
      redactionCount: 2,
      metadataStripped: true,
    }),
    ...overrides,
  };
}

describe("buildRedactedExport", () => {
  it("produces a valid ZIP with anonymized report, screenshots, and notes", async () => {
    const { zip, summary } = await buildRedactedExport(deps(), "INC-1", DEFAULT_REDACTED_EXPORT_OPTIONS);
    const entries = readZip(zip);
    const byPath = new Map(entries.map((e) => [e.path, e.data]));

    // report text was anonymized via the shared anonymizer
    expect(byPath.get("report/report.md")!.toString("utf8")).toBe("ANON_HOST_1 at ANON_IP_1");
    // notes always present
    expect(byPath.has("REDACTION-NOTES.txt")).toBe(true);
    // both screenshots included + redacted by the injected redactor
    expect(byPath.get("screenshots/shot-001.png")!.toString("utf8")).toBe("REDACTED:raw-shot-001.png");
    expect(byPath.has("screenshots/shot-002.png")).toBe(true);

    expect(summary.screenshotCount).toBe(2);
    expect(summary.screenshotsBlurred).toBe(2);
    expect(summary.screenshotRedactions).toBe(4);
    expect(summary.metadataStripped).toBe(2);
  });

  it("omits screenshots when excluded and never calls the image redactor", async () => {
    let called = 0;
    const d = deps({
      redactImage: async (buf) => {
        called++;
        return { buffer: buf, blurred: false, redactionCount: 0, metadataStripped: true };
      },
    });
    const { zip, summary } = await buildRedactedExport(d, "INC-1", { ...DEFAULT_REDACTED_EXPORT_OPTIONS, includeScreenshots: false });
    const paths = readZip(zip).map((e) => e.path);
    expect(paths.some((p) => p.startsWith("screenshots/"))).toBe(false);
    expect(called).toBe(0);
    expect(summary.screenshotCount).toBe(0);
  });

  it("tokenizes victim-org domains from the customer store even when absent from the timeline", async () => {
    const d = deps({
      customerStore: { load: async () => ({ domains: ["victimcorp.com"], emails: ["ceo@victimcorp.com"] }) } as unknown as RedactedExportDeps["customerStore"],
      reportWriter: {
        redactedReportContents: async (_caseId: string, redact: (s: string) => string) => ({
          markdown: redact("breach at victimcorp.com affecting ceo@victimcorp.com"),
          html: "<h1>r</h1>", findingsCsv: "f", iocsCsv: "i", timelineCsv: "t", forensicTimelineCsv: "ft", stateJson: "{}",
        }),
      },
    });
    const { zip } = await buildRedactedExport(d, "INC-1", DEFAULT_REDACTED_EXPORT_OPTIONS);
    const md = new Map(readZip(zip).map((e) => [e.path, e.data])).get("report/report.md")!.toString("utf8");
    expect(md).not.toContain("victimcorp.com");
    expect(md).toContain("ANON_DOMAIN_1");
    expect(md).toContain("ANON_EMAIL_1");
  });

  it("includes only the report markdown/html when CSVs, state, and screenshots are excluded", async () => {
    const { zip } = await buildRedactedExport(deps(), "INC-1", {
      includeReport: true, includeCsvs: false, includeStateJson: false, includeScreenshots: false, blurScreenshots: false,
    });
    const paths = readZip(zip).map((e) => e.path).sort();
    expect(paths).toEqual(["REDACTION-NOTES.txt", "export-manifest.json", "report/report.html", "report/report.md"]);
  });

  it("ships an export-manifest.json with a correct sha256/bytes for every other file (#79)", async () => {
    const { zip } = await buildRedactedExport(deps(), "INC-1", DEFAULT_REDACTED_EXPORT_OPTIONS);
    const entries = readZip(zip);
    const manifestEntry = entries.find((e) => e.path === "export-manifest.json");
    expect(manifestEntry).toBeDefined();
    const manifest = JSON.parse(manifestEntry!.data.toString("utf8"));

    expect(manifest.caseId).toBe("INC-1");
    expect(typeof manifest.exportedAt).toBe("string");    // live wall-clock from the orchestrator
    expect(new Date(manifest.exportedAt).toString()).not.toBe("Invalid Date");
    expect(typeof manifest.generatedBy).toBe("string");
    expect(manifest.generatedBy.length).toBeGreaterThan(0);

    // Every non-manifest file is listed with a verifiable hash + byte count; the manifest excludes itself.
    const others = entries.filter((e) => e.path !== "export-manifest.json");
    expect(manifest.totalFiles).toBe(others.length);
    expect(manifest.files.some((f: { path: string }) => f.path === "export-manifest.json")).toBe(false);
    const byPath = new Map(others.map((e) => [e.path, e.data]));
    for (const f of manifest.files) {
      const data = byPath.get(f.path)!;
      expect(data).toBeDefined();
      expect(f.bytes).toBe(data.length);
      expect(f.sha256).toBe(createHash("sha256").update(data).digest("hex"));
    }
    expect(manifest.totalBytes).toBe(others.reduce((n, e) => n + e.data.length, 0));
  });
});
