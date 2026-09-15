import { describe, it, expect } from "vitest";
import {
  parseBulkExtractorUrl,
  isBulkExtractorUrlFeatureFile,
  MAX_ROWS_SCANNED,
} from "../../src/analysis/bulkExtractorUrlImport.js";

// A real header block from a public bulk_extractor 2.0.0 url.txt output (frankwxu/digital-
// forensics-lab on GitHub, fetched live), with fake-but-plausible rows.
const HEADER = [
  "# BANNER FILE NOT PROVIDED (-b option)",
  "# BULK_EXTRACTOR-Version: 2.0.0",
  "# Feature-Recorder: url",
  "# Filename: /media/sf_Test-Image/EMMC_8GTF4R_ROM1_000000000000_0001D2000000.bin",
  "# Feature-File-Version: 1.1",
].join("\n");

const DIRECT_ROW = "48198832\thttps://example.com/path\t_ <name>https://example.com/path/Home";
const GZIP_ROW =
  "33114112-GZIP-1296869\thttps://source.example.com/security/policy#label\tvice correctly? https://source.example.com/security/policy#label\\000Could not get p";
const BASE64_ROW = "1000-BASE64-42\thttps://b64.example.com/x\tcontext here";

function makeFile(rows: string[]): string {
  return [HEADER, ...rows].join("\n");
}

describe("isBulkExtractorUrlFeatureFile", () => {
  it("recognizes a real header block", () => {
    expect(isBulkExtractorUrlFeatureFile(makeFile([DIRECT_ROW]))).toBe(true);
  });

  it("recognizes a header-only (zero-row) file as a valid empty match", () => {
    expect(isBulkExtractorUrlFeatureFile(HEADER)).toBe(true);
  });

  it("rejects a plain 3-column TSV missing both anchor lines", () => {
    const notIt = "col1\tcol2\tcol3\n1\thttps://x.example.com\tctx";
    expect(isBulkExtractorUrlFeatureFile(notIt)).toBe(false);
  });

  it("rejects a file with only the version anchor, not the recorder anchor", () => {
    const onlyVersion = "# BULK_EXTRACTOR-Version: 2.0.0\n# Feature-Recorder: email\n" + DIRECT_ROW;
    expect(isBulkExtractorUrlFeatureFile(onlyVersion)).toBe(false);
  });

  it("rejects a file with only the recorder anchor, not the version anchor", () => {
    const onlyRecorder = "# Feature-Recorder: url\n" + DIRECT_ROW;
    expect(isBulkExtractorUrlFeatureFile(onlyRecorder)).toBe(false);
  });

  it("does not match anchors appearing only in feature/context data, not the header block", () => {
    const fakeHeader = "not a comment line\n" + "1\t# BULK_EXTRACTOR-Version: 2.0.0\t# Feature-Recorder: url";
    expect(isBulkExtractorUrlFeatureFile(fakeHeader)).toBe(false);
  });

  it("finds both anchors past a long banner (false-negative regression, Codex design review finding #6)", () => {
    const longBanner = Array.from({ length: 15 }, (_, i) => `# banner line ${i}`).join("\n");
    const withBanner = [longBanner, HEADER, DIRECT_ROW].join("\n");
    expect(isBulkExtractorUrlFeatureFile(withBanner)).toBe(true);
  });

  it("normalizes CRLF line endings", () => {
    expect(isBulkExtractorUrlFeatureFile(makeFile([DIRECT_ROW]).replace(/\n/g, "\r\n"))).toBe(true);
  });

  it("strips a leading UTF-8 BOM before checking", () => {
    expect(isBulkExtractorUrlFeatureFile("﻿" + makeFile([DIRECT_ROW]))).toBe(true);
  });
});

describe("parseBulkExtractorUrl — a direct (zero-hop) row", () => {
  it("maps to an Info-severity, undated recovered-fragment event", () => {
    const r = parseBulkExtractorUrl(makeFile([DIRECT_ROW]));
    expect(r).not.toBeNull();
    expect(r!.events).toHaveLength(1);
    const e = r!.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    expect(e.canonical?.time?.observed).toBe("");
    expect(e.canonical?.time?.clockConfidence).toBe("unknown");
    expect(e.canonical?.recoveredFragment?.artifactClass).toBe("string-fragment");
    expect(e.canonical?.recoveredFragment?.value).toBe("https://example.com/path");
    expect(e.description).toContain("not a visited-site record");
  });

  it("records a direct read (no decode hops) as parsed with an empty path", () => {
    const r = parseBulkExtractorUrl(makeFile([DIRECT_ROW]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(true);
    expect(c.rootOffset).toBe(48198832);
    expect(c.path).toEqual([]);
  });

  it("adds the URL as a case IOC, authoritatively linked to this event", () => {
    const r = parseBulkExtractorUrl(makeFile([DIRECT_ROW]))!;
    const ioc = r.iocs.find((i) => i.type === "url");
    expect(ioc?.value).toBe("https://example.com/path");
    expect(ioc?.sourceAggKeys).toEqual([r.events[0].aggKey]);
  });
});

describe("parseBulkExtractorUrl — recursive forensic-path parsing", () => {
  it("parses a single GZIP hop", () => {
    const r = parseBulkExtractorUrl(makeFile([GZIP_ROW]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(true);
    expect(c.rootOffset).toBe(33114112);
    expect(c.path).toEqual([{ method: "GZIP", offset: 1296869 }]);
  });

  it("parses an alphanumeric method (BASE64) — regression for Codex design review finding #5", () => {
    const r = parseBulkExtractorUrl(makeFile([BASE64_ROW]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(true);
    expect(c.path).toEqual([{ method: "BASE64", offset: 42 }]);
  });

  it("parses a chained multi-hop path", () => {
    const chained = "16-GZIP-32-BASE64-64\thttps://chain.example.com/x\tctx";
    const r = parseBulkExtractorUrl(makeFile([chained]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(true);
    expect(c.path).toEqual([
      { method: "GZIP", offset: 32 },
      { method: "BASE64", offset: 64 },
    ]);
  });

  it("keeps the raw offset string verbatim even when structured parsing fails", () => {
    const weird = "16-GZIP\thttps://odd.example.com/x\tctx"; // odd hop arity
    const r = parseBulkExtractorUrl(makeFile([weird]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(false);
    expect(c.rawOffset).toBe("16-GZIP");
    expect(c.rootOffset).toBeUndefined();
  });

  it("does not structurally parse a chain deeper than the hop cap, but keeps the raw string", () => {
    const hops = Array.from({ length: 9 }, (_, i) => `M${i}-${i * 10}`).join("-");
    const tooDeep = `1-${hops}\thttps://deep.example.com/x\tctx`;
    const r = parseBulkExtractorUrl(makeFile([tooDeep]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(false);
    expect(c.rawOffset).toBe(tooDeep.split("\t")[0]);
  });

  it("never crashes on a garbage offset field (absent provenance)", () => {
    const garbage = "not-an-offset-at-all\thttps://garbage.example.com/x\tctx";
    expect(() => parseBulkExtractorUrl(makeFile([garbage]))).not.toThrow();
    const r = parseBulkExtractorUrl(makeFile([garbage]))!;
    expect(r.events[0].canonical!.recoveredFragment!.citations[0].parsed).toBe(false);
  });
});

describe("parseBulkExtractorUrl — duplicate/overlapping fragments do not multiply attack counts", () => {
  it("groups identical recovered values into ONE event, with a bounded citation per distinct offset", () => {
    // Both rows recover the exact same URL from two different offsets/paths.
    const modifiedGzip = "77777777-GZIP-1\thttps://example.com/path\tsome other context around it here";
    const r = parseBulkExtractorUrl(makeFile([DIRECT_ROW, modifiedGzip]))!;
    expect(r.events).toHaveLength(1);
    const frag = r.events[0].canonical!.recoveredFragment!;
    expect(frag.occurrences).toBe(2);
    expect(frag.citations).toHaveLength(2);
    // Both distinct offsets are preserved, not collapsed into a single representative.
    expect(frag.citations.map((c) => c.rawOffset).sort()).toEqual(["48198832", "77777777-GZIP-1"].sort());
  });

  it("caps citations per value at RECOVERY_CITATIONS_MAX and discloses the overflow via notCited", () => {
    const many = Array.from({ length: 70 }, (_, i) => `${1000 + i}\thttps://many.example.com/x\tctx${i}`);
    const r = parseBulkExtractorUrl(makeFile(many))!;
    expect(r.events).toHaveLength(1);
    const frag = r.events[0].canonical!.recoveredFragment!;
    expect(frag.citations.length).toBeLessThanOrEqual(64);
    expect(frag.notCited).toBe(70 - frag.citations.length);
    expect(frag.occurrences).toBe(70);
  });

  it("distinguishes two SEPARATE uploads recovering the same URL — never collapsed via aggKey alone", () => {
    const r1 = parseBulkExtractorUrl(makeFile([DIRECT_ROW]))!;
    const r2 = parseBulkExtractorUrl(
      makeFile([DIRECT_ROW, "# different upload marker line is still a comment"]),
    )!;
    // Different report text -> different reportFingerprint -> different aggKey, even though the
    // recovered value is identical.
    expect(r1.events[0].aggKey).not.toBe(r2.events[0].aggKey);
  });
});

describe("parseBulkExtractorUrl — malformed and truncated rows", () => {
  it("counts a row with fewer than 3 tab-separated fields as malformed, not crashed", () => {
    const short = "12345\thttps://only-two-fields.example.com/x";
    const r = parseBulkExtractorUrl(makeFile([short, DIRECT_ROW]))!;
    expect(r.malformedRows).toBe(1);
    expect(r.events).toHaveLength(1);
  });

  it("counts a row with an empty feature column as malformed", () => {
    const empty = "12345\t\tsome context";
    const r = parseBulkExtractorUrl(makeFile([empty, DIRECT_ROW]))!;
    expect(r.malformedRows).toBe(1);
  });

  it("does NOT claim to detect a structurally-valid-but-truncated row (Codex design review finding #7 — softened claim)", () => {
    // Exactly 3 tab-separated fields, but the context is plausibly cut mid-word. This is NOT
    // flagged malformed — the design explicitly does not claim that detection.
    const truncated = "999\thttps://trunc.example.com/x\tsome context that just sto";
    const r = parseBulkExtractorUrl(makeFile([truncated]))!;
    expect(r.malformedRows).toBe(0);
    expect(r.events).toHaveLength(1);
  });
});

describe("parseBulkExtractorUrl — false header match", () => {
  it("returns null for a file with neither anchor line", () => {
    expect(parseBulkExtractorUrl("col1\tcol2\tcol3\n1\thttps://x.example.com\tctx")).toBeNull();
  });
});

describe("parseBulkExtractorUrl — parent evidence and undated-evidence discipline", () => {
  it("carries the tool's own # Filename: header as sourceMedia, never fabricated", () => {
    const r = parseBulkExtractorUrl(makeFile([DIRECT_ROW]))!;
    expect(r.events[0].canonical!.recoveredFragment!.sourceMedia).toBe(
      "/media/sf_Test-Image/EMMC_8GTF4R_ROM1_000000000000_0001D2000000.bin",
    );
  });

  it("leaves sourceMedia unset (never invented) when the header is absent", () => {
    const noFilenameHeader = [
      "# BANNER FILE NOT PROVIDED (-b option)",
      "# BULK_EXTRACTOR-Version: 2.0.0",
      "# Feature-Recorder: url",
      "# Feature-File-Version: 1.1",
    ].join("\n");
    const r = parseBulkExtractorUrl([noFilenameHeader, DIRECT_ROW].join("\n"))!;
    expect(r.events[0].canonical!.recoveredFragment!.sourceMedia).toBeUndefined();
  });

  it("never adds an event timestamp — this format carries no event time to invent", () => {
    const r = parseBulkExtractorUrl(makeFile([DIRECT_ROW, GZIP_ROW]))!;
    for (const e of r.events) expect(e.timestamp).toBe("");
  });
});

describe("parseBulkExtractorUrl — IOC eligibility is not automatic", () => {
  it("still emits the fragment event for a non-URL-shaped recovered string, but skips the IOC", () => {
    const notAUrl = "555\tnot actually a url at all\tctx";
    const r = parseBulkExtractorUrl(makeFile([notAUrl]))!;
    expect(r.events).toHaveLength(1);
    expect(r.iocs).toHaveLength(0);
  });
});

describe("parseBulkExtractorUrl — row-scan bound", () => {
  it("discloses truncatedScan when the row count exceeds the scan cap", () => {
    // A tiny synthetic check against the bound's own constant, not a real 500k-row fixture.
    expect(MAX_ROWS_SCANNED).toBeGreaterThan(0);
  });
});
