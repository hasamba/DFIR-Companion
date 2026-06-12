import { describe, it, expect } from "vitest";
import {
  applyAnonDeep,
  resolveRedactedExportOptions,
  redactedExportPolicy,
  assembleRedactedEntries,
  buildRedactionNotes,
  redactedExportFilename,
  safeArchiveName,
  DEFAULT_REDACTED_EXPORT_OPTIONS,
  type RedactedReportContents,
  type RedactionSummary,
} from "../../src/analysis/redactedExport.js";
import { createAnonymizer, SECRET_PLACEHOLDER, type KnownEntities } from "../../src/analysis/anonymize.js";

const KNOWN: KnownEntities = {
  hosts: ["VICTIM-PC"],
  accounts: [],
  internalDomains: ["corp.local"],
};

describe("redactedExportPolicy", () => {
  it("enables every category and secret redaction", () => {
    const p = redactedExportPolicy();
    expect(p.enabled).toBe(true);
    expect(p.redactSecrets).toBe(true);
    expect(Object.values(p.categories).every(Boolean)).toBe(true);
  });
});

describe("resolveRedactedExportOptions", () => {
  it("defaults everything to true when no query params are given", () => {
    expect(resolveRedactedExportOptions({})).toEqual(DEFAULT_REDACTED_EXPORT_OPTIONS);
  });

  it("honors falsy opt-out tokens but keeps other defaults", () => {
    const opts = resolveRedactedExportOptions({ screenshots: "0", blur: "false", state: "no" });
    expect(opts.includeScreenshots).toBe(false);
    expect(opts.blurScreenshots).toBe(false);
    expect(opts.includeStateJson).toBe(false);
    expect(opts.includeReport).toBe(true);
    expect(opts.includeCsvs).toBe(true);
  });

  it("treats present truthy values as true", () => {
    expect(resolveRedactedExportOptions({ blur: "1", screenshots: "yes" }).blurScreenshots).toBe(true);
  });
});

describe("applyAnonDeep", () => {
  it("tokenizes strings in nested objects/arrays while preserving structure and non-strings", () => {
    const anon = createAnonymizer(redactedExportPolicy(), KNOWN);
    const state = {
      events: [
        { description: "VICTIM-PC contacted 10.0.0.5", severity: "High", count: 3, ok: true },
        { description: "external C2 at 203.0.113.9", path: "C:\\Users\\jdoe\\evil.exe" },
      ],
      note: null,
    };
    const out = applyAnonDeep(state, (s) => anon.apply(s));

    // internal host + internal IP tokenized; counts/booleans/null untouched
    expect(out.events[0].description).toBe("ANON_HOST_1 contacted ANON_IP_1");
    expect(out.events[0].count).toBe(3);
    expect(out.events[0].ok).toBe(true);
    expect(out.note).toBeNull();
    // public adversary IP preserved; user profile path tokenized
    expect(out.events[1].description).toContain("203.0.113.9");
    expect(out.events[1].path).toBe("C:\\Users\\ANON_USER_1\\evil.exe");
    // original input is not mutated (immutability)
    expect(state.events[0].description).toBe("VICTIM-PC contacted 10.0.0.5");
  });

  it("one-way redacts secrets", () => {
    const anon = createAnonymizer(redactedExportPolicy(), KNOWN);
    const out = applyAnonDeep({ line: "password=Sup3rSecret!" }, (s) => anon.apply(s));
    expect(out.line).toBe(`password=${SECRET_PLACEHOLDER}`);
  });
});

const CONTENTS: RedactedReportContents = {
  markdown: "# md", html: "<h1>h</h1>", findingsCsv: "f", iocsCsv: "i",
  timelineCsv: "t", forensicTimelineCsv: "ft", stateJson: "{}",
};

describe("assembleRedactedEntries", () => {
  it("includes all parts by default and always writes the notes file", () => {
    const entries = assembleRedactedEntries({
      contents: CONTENTS,
      screenshots: [{ name: "shot-001.png", data: Buffer.from([1, 2, 3]) }],
      notes: "NOTES",
      options: DEFAULT_REDACTED_EXPORT_OPTIONS,
    });
    const paths = entries.map((e) => e.path);
    expect(paths).toContain("REDACTION-NOTES.txt");
    expect(paths).toContain("report/report.md");
    expect(paths).toContain("report/report.html");
    expect(paths).toContain("report/findings.csv");
    expect(paths).toContain("report/state-export.json");
    expect(paths).toContain("screenshots/shot-001.png");
  });

  it("omits sections the analyst excluded", () => {
    const entries = assembleRedactedEntries({
      contents: CONTENTS,
      screenshots: [{ name: "shot-001.png", data: Buffer.from([1]) }],
      notes: "NOTES",
      options: { includeReport: false, includeCsvs: false, includeStateJson: false, includeScreenshots: false, blurScreenshots: false },
    });
    expect(entries.map((e) => e.path)).toEqual(["REDACTION-NOTES.txt"]);
  });

  it("never lets a screenshot filename escape the screenshots/ prefix (zip-slip)", () => {
    const entries = assembleRedactedEntries({
      contents: CONTENTS,
      screenshots: [{ name: "../../report/report.md", data: Buffer.from([9]) }],
      notes: "NOTES",
      options: DEFAULT_REDACTED_EXPORT_OPTIONS,
    });
    const shotPaths = entries.map((e) => e.path).filter((p) => p.startsWith("screenshots/"));
    expect(shotPaths).toEqual(["screenshots/report.md"]);
    expect(shotPaths[0]).not.toContain("..");
  });
});

describe("safeArchiveName", () => {
  it("strips directory components and traversal", () => {
    expect(safeArchiveName("../../etc/passwd")).toBe("passwd");
    expect(safeArchiveName("a/b/c.png")).toBe("c.png");
    expect(safeArchiveName("..\\..\\evil.exe")).toBe("evil.exe");
    expect(safeArchiveName("shot-001.png")).toBe("shot-001.png");
    expect(safeArchiveName("")).toBe("file");
  });
});

describe("buildRedactionNotes", () => {
  const base: RedactionSummary = {
    caseId: "INC-2026-001",
    options: DEFAULT_REDACTED_EXPORT_OPTIONS,
    screenshotCount: 4,
    screenshotsBlurred: 2,
    screenshotRedactions: 7,
    metadataStripped: 4,
  };

  it("states the case, the caveat, and the exclusions", () => {
    const notes = buildRedactionNotes(base);
    expect(notes).toContain("INC-2026-001");
    expect(notes).toContain("7 region(s)");
    expect(notes).toContain("auto-detected");
    expect(notes).toContain("Faces");
    expect(notes).toContain(".env");
    expect(notes).toContain(SECRET_PLACEHOLDER);
  });

  it("drops the screenshot caveat when screenshots are excluded", () => {
    const notes = buildRedactionNotes({ ...base, options: { ...base.options, includeScreenshots: false } });
    expect(notes).toContain("Included in this package: no");
    expect(notes).not.toContain("region(s)");
  });
});

describe("redactedExportFilename", () => {
  it("builds the download name", () => {
    expect(redactedExportFilename("INC-2026-001")).toBe("case-INC-2026-001-redacted.zip");
  });
});
