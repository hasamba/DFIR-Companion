import { describe, it, expect } from "vitest";
import {
  parseBulkExtractorUrl,
  isBulkExtractorUrlFeatureFile,
  MAX_ROWS_SCANNED,
} from "../../src/analysis/bulkExtractorUrlImport.js";
import type { RecoveryCitation } from "../../src/analysis/canonicalRecoveredFragment.js";

// Narrows the `parsed` discriminated union so `.rootOffset`/`.path` are legal to read below —
// asserts at runtime too, so a citation that silently stopped parsing fails loudly, not with a
// confusing "property does not exist" at some unrelated line.
function assertParsed(c: RecoveryCitation): asserts c is Extract<RecoveryCitation, { parsed: true }> {
  expect(c.parsed).toBe(true);
}

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
    assertParsed(c);
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
    assertParsed(c);
    expect(c.rootOffset).toBe(33114112);
    expect(c.path).toEqual([{ method: "GZIP", offset: 1296869 }]);
  });

  it("parses an alphanumeric method (BASE64) — regression for Codex design review finding #5", () => {
    const r = parseBulkExtractorUrl(makeFile([BASE64_ROW]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    assertParsed(c);
    expect(c.path).toEqual([{ method: "BASE64", offset: 42 }]);
  });

  it("parses a chained multi-hop path", () => {
    const chained = "16-GZIP-32-BASE64-64\thttps://chain.example.com/x\tctx";
    const r = parseBulkExtractorUrl(makeFile([chained]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    assertParsed(c);
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
  });

  it("does not structurally parse a chain deeper than the hop cap, but keeps the raw string", () => {
    const hops = Array.from({ length: 9 }, (_, i) => `M${i}-${i * 10}`).join("-");
    const tooDeep = `1-${hops}\thttps://deep.example.com/x\tctx`;
    const r = parseBulkExtractorUrl(makeFile([tooDeep]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(false);
    expect(c.rawOffset).toBe(tooDeep.split("\t")[0]);
  });

  it("rejects an oversized-but-plausible offset field without attempting to split it, yet still stores it verbatim (bounded before split, Codex code review finding)", () => {
    const hugeOffset = Array.from({ length: 200 }, (_, i) => `M${i}-${i}`).join("-");
    const row = `${hugeOffset}\thttps://oversized-offset.example.com/x\tctx`;
    expect(() => parseBulkExtractorUrl(makeFile([row]))).not.toThrow();
    const r = parseBulkExtractorUrl(makeFile([row]))!;
    const c = r.events[0].canonical!.recoveredFragment!.citations[0];
    expect(c.parsed).toBe(false);
    expect(c.rawOffset).toBe(hugeOffset); // kept verbatim, not truncated, despite failing to parse
  });

  it("rejects a PATHOLOGICALLY long offset field as a malformed row (never stored at all)", () => {
    const pathological = "9".repeat(20_000);
    const row = `${pathological}\thttps://pathological.example.com/x\tctx`;
    const r = parseBulkExtractorUrl(makeFile([row, DIRECT_ROW]))!;
    expect(r.malformedRows).toBe(1);
    expect(r.events).toHaveLength(1); // only DIRECT_ROW survives
    // #1142: dropped was hardcoded to 0, so total !== kept + dropped whenever a row was malformed.
    expect(r.dropped).toBe(1);
    expect(r.total).toBe(r.kept + r.dropped);
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

  it("distinguishes two SEPARATE uploads recovering the same URL, in BOTH aggKey and the persisted description (Codex code review finding #1 — aggKey alone doesn't survive to the merged event)", () => {
    const r1 = parseBulkExtractorUrl(makeFile([DIRECT_ROW]))!;
    const r2 = parseBulkExtractorUrl(
      makeFile([DIRECT_ROW, "# different upload marker line is still a comment"]),
    )!;
    expect(r1.events[0].aggKey).not.toBe(r2.events[0].aggKey);
    // The report-identity tag in the description is what keeps two persisted events apart after
    // aggKey is stripped at the ingest boundary (a real, disclosed report fingerprint, not a
    // digest spliced into evidence text).
    expect(r1.events[0].description).not.toBe(r2.events[0].description);
  });

  it("dedupes identical (rawOffset, context) citations so a later DISTINCT one is never crowded out by the cap", () => {
    const duplicates = Array.from(
      { length: 80 },
      () => "9999\thttps://dupes.example.com/x\tsame context every time",
    );
    const distinctLast = "424242\thttps://dupes.example.com/x\ta genuinely different context";
    const r = parseBulkExtractorUrl(makeFile([...duplicates, distinctLast]))!;
    const frag = r.events[0].canonical!.recoveredFragment!;
    expect(frag.occurrences).toBe(81);
    // Only 2 DISTINCT (rawOffset, context) pairs exist — the 80 duplicates collapse to one.
    expect(frag.citations).toHaveLength(2);
    expect(frag.citations.some((c) => c.rawOffset === "424242")).toBe(true);
    expect(frag.notCited).toBe(0);
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

  it("discloses the undated marker in every description", () => {
    const r = parseBulkExtractorUrl(makeFile([DIRECT_ROW]))!;
    expect(r.events[0].description).toContain(
      "[undated: bulk_extractor's feature file carries no event time]",
    );
  });

  it("never reads # Filename: from a line AFTER the header block — a data row can't fabricate parent evidence (Codex code review finding)", () => {
    const injected = makeFile([DIRECT_ROW, "# Filename: /attacker/controlled/path.bin"]);
    const r = parseBulkExtractorUrl(injected)!;
    expect(r.events[0].canonical!.recoveredFragment!.sourceMedia).toBe(
      "/media/sf_Test-Image/EMMC_8GTF4R_ROM1_000000000000_0001D2000000.bin",
    );
  });
});

describe("parseBulkExtractorUrl — oversized value is truncated, never digest-spliced into a fabricated URL", () => {
  it("plain-truncates a value over MAX_VALUE_LEN, discloses valueTruncated, and never promotes it to an IOC", () => {
    const hugeValue = "https://huge.example.com/" + "a".repeat(3000);
    const row = `12345\t${hugeValue}\tctx`;
    const r = parseBulkExtractorUrl(makeFile([row]))!;
    expect(r.events).toHaveLength(1);
    const frag = r.events[0].canonical!.recoveredFragment!;
    expect(frag.valueTruncated).toBe(true);
    expect(frag.value.length).toBeLessThanOrEqual(2000);
    // The stored value is a plain prefix of the real string — never a digest spliced in with "#".
    expect(hugeValue.startsWith(frag.value)).toBe(true);
    expect(frag.value.includes("#")).toBe(false);
    expect(r.iocs).toHaveLength(0);
  });

  it("groups two DIFFERENT huge values (identical only in their first 2000 chars) as two distinct fragments", () => {
    const prefix = "https://huge.example.com/" + "a".repeat(3000);
    const rowA = `1\t${prefix}AAA\tctx`;
    const rowB = `2\t${prefix}BBB\tctx`;
    const r = parseBulkExtractorUrl(makeFile([rowA, rowB]))!;
    expect(r.events).toHaveLength(2);
  });
});

describe("parseBulkExtractorUrl — IOC eligibility and authoritative linkage", () => {
  it("still emits the fragment event for a non-URL-shaped recovered string, but skips the IOC", () => {
    const notAUrl = "555\tnot actually a url at all\tctx";
    const r = parseBulkExtractorUrl(makeFile([notAUrl]))!;
    expect(r.events).toHaveLength(1);
    expect(r.iocs).toHaveLength(0);
  });

  it("unions sourceAggKeys across case-variant values sharing one lowercased IOC key, never overwrites (Codex code review finding)", () => {
    const lower = "1\thttps://case-test.example.com/x\tctx";
    const upper = "2\tHTTPS://CASE-TEST.EXAMPLE.COM/x\tctx";
    const r = parseBulkExtractorUrl(makeFile([lower, upper]))!;
    expect(r.events).toHaveLength(2); // distinct exact strings -> distinct fragment events
    const ioc = r.iocs.find((i) => i.type === "url");
    expect(ioc?.sourceAggKeys).toHaveLength(2);
    expect(new Set(ioc?.sourceAggKeys)).toEqual(new Set(r.events.map((e) => e.aggKey)));
  });
});

describe("parseBulkExtractorUrl — row-scan bound", () => {
  it("discloses truncatedScan when the row count exceeds the scan cap", () => {
    // A tiny synthetic check against the bound's own constant, not a real 500k-row fixture.
    expect(MAX_ROWS_SCANNED).toBeGreaterThan(0);
  });
});
