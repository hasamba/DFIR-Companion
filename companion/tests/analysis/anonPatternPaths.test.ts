import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { DiscoveredEntitiesStore } from "../../src/analysis/anonDiscovered.js";
import { AnonControlStore } from "../../src/analysis/anonControl.js";
import { caseMasker } from "../../src/analysis/ai/maskRequest.js";
import type { ProviderCallContext } from "../../src/analysis/ai/providerCallContext.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { ocrRedactImage, type OcrWord } from "../../src/analysis/ocrRedact.js";
import { buildRedactedExport, type RedactedExportDeps } from "../../src/reports/redactedExportBuilder.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { DEFAULT_REDACTED_EXPORT_OPTIONS } from "../../src/analysis/redactedExport.js";
import type { AnonPolicy, CustomEntity, KnownEntities } from "../../src/analysis/anonymize.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

// #2946: a wildcard pattern or a CIDR range must apply on every path custom entities apply to —
// the shared AI masking step (which the Jev routes use too), screenshot OCR redaction and the
// redacted export. A pattern that works on one path and not another is a silent leak.

const PATTERNS: CustomEntity[] = [
  { value: "prod-*", category: "HOST", match: "pattern" },
  { value: "10.20.0.0/16", category: "IP", match: "pattern" },
];
const TEXT = "prod-web01 called 10.20.7.7 then prod-db02";

describe("the shared AI masking step (AI calls and Jev)", () => {
  it("masks wildcard and range matches and restores them", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-anonpat-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await new CustomEntitiesStore(cases).save("c1", PATTERNS);
    const ctx: ProviderCallContext = {
      log: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as never,
      opts: {
        anonStore: new AnonControlStore(cases),
        customEntitiesStore: new CustomEntitiesStore(cases),
        discoveredStore: new DiscoveredEntitiesStore(cases),
      },
    };
    const masker = await caseMasker(ctx, "c1", emptyState("c1"));
    const out = masker.mask(TEXT);
    expect(out).not.toMatch(/prod-web01|prod-db02|10\.20\.7\.7/);
    expect(out).toMatch(/^ANON_HOST_\d+ called ANON_IP_\d+ then ANON_HOST_\d+$/);
  });
});

describe("screenshot OCR redaction", () => {
  it("boxes words a pattern or a range covers", async () => {
    const img = await sharp({ create: { width: 300, height: 60, channels: 3, background: "#fff" } })
      .png()
      .toBuffer();
    const word = (text: string, x: number): OcrWord => ({
      text,
      bbox: { x, y: 10, w: 60, h: 20 },
      confidence: 95,
    });
    const policy: AnonPolicy = {
      enabled: true,
      categories: {
        IP: true,
        EMAIL: true,
        USER: true,
        HOST: true,
        DOMAIN: true,
        PATH: true,
        CMD: true,
        REG: true,
        CARD: true,
        PHONE: true,
        NATID: true,
      },
      redactSecrets: false,
      maskPublicIps: true,
    };
    const known: KnownEntities = { hosts: [], accounts: [], internalDomains: [], custom: PATTERNS };
    const words = [
      word("prod-web01", 0),
      word("unrelated", 70),
      word("10.20.7.7", 140),
      word("myprod-x", 210),
    ];
    const result = await ocrRedactImage(img, policy, known, { recognize: async () => words });
    expect(result.redactions.map((w) => w.text).sort()).toEqual(["10.20.7.7", "prod-web01"]);
  });
});

describe("the redacted export", () => {
  it("tokenizes wildcard and range matches in the report", async () => {
    const state = { forensicTimeline: [], findings: [], iocs: [] } as unknown as InvestigationState;
    const deps: RedactedExportDeps = {
      store: {} as RedactedExportDeps["store"],
      stateStore: { load: async () => state } as unknown as RedactedExportDeps["stateStore"],
      customEntities: { load: async () => PATTERNS } as unknown as RedactedExportDeps["customEntities"],
      discoveredEntities: {
        load: async () => ({ discovered: [], suppressed: [] }),
      } as unknown as RedactedExportDeps["discoveredEntities"],
      ocrRunner: { recognize: async () => [] },
      reportWriter: {
        redactedReportContents: async (_caseId: string, redact: (s: string) => string) => ({
          markdown: redact(TEXT),
          html: "<h1>r</h1>",
          findingsCsv: "f",
          iocsCsv: "i",
          timelineCsv: "t",
          forensicTimelineCsv: "ft",
          stateJson: "{}",
        }),
      },
      listScreenshots: async () => [],
      readScreenshot: async () => Buffer.alloc(0),
    };
    const { zip } = await buildRedactedExport(deps, "INC-1", DEFAULT_REDACTED_EXPORT_OPTIONS);
    const md = readZip(zip)
      .find((e) => e.path === "report/report.md")!
      .data.toString("utf8");
    expect(md).toBe("ANON_HOST_1 called ANON_IP_1 then ANON_HOST_2");
  });
});
