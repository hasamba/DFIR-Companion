import { describe, it, expect } from "vitest";
import { parseOlevbaResult, isOlevbaResult } from "../../src/analysis/olevbaResultImport.js";

// Shape verified live against oletools' olevba.py JSON-building code and a real 0.60.2 `-j`
// report: a top-level array with a MetaInformation entry plus one entry per document/container.
function meta(overrides: Record<string, unknown> = {}) {
  return { type: "MetaInformation", script_name: "olevba", version: "0.60.2", ...overrides };
}

function resultEntry(overrides: Record<string, unknown> = {}) {
  return {
    type: "OLE",
    file: "sample.doc",
    json_conversion_successful: true,
    macros: [],
    analysis: [],
    ...overrides,
  };
}

function doc(entries: unknown[], metaOverrides: Record<string, unknown> = {}): string {
  return JSON.stringify([meta(metaOverrides), ...entries]);
}

const AUTOEXEC = {
  type: "AutoExec",
  keyword: "AutoOpen",
  description: "Runs when the Word document is opened",
};
const DOWNLOAD_SUSPICIOUS = {
  type: "Suspicious",
  keyword: "URLDownloadToFile",
  description: "May download files from the Internet",
};
const BENIGN_SUSPICIOUS = {
  type: "Suspicious",
  keyword: "RegOpenKeyEx",
  description: "May read or write registry keys",
};
const STOMPING = {
  type: "Suspicious",
  keyword: "VBA Stomping",
  description: "Contains VBA stomping (VBA source code and P-code are different)",
};
const IOC_URL = { type: "IOC", keyword: "http://evil.example/payload.exe", description: "URL" };

describe("isOlevbaResult", () => {
  it("recognizes a real olevba results document", () => {
    expect(isOlevbaResult(JSON.parse(doc([resultEntry()])))).toBe(true);
  });

  it("accepts a macro-free document whose analysis is null, not an array", () => {
    expect(isOlevbaResult(JSON.parse(doc([resultEntry({ analysis: null })])))).toBe(true);
  });

  it("rejects a document with a MetaInformation entry but no result entry", () => {
    expect(isOlevbaResult(JSON.parse(doc([])))).toBe(false);
  });

  it("rejects a result entry with no MetaInformation anchor", () => {
    expect(isOlevbaResult(JSON.parse(JSON.stringify([resultEntry()])))).toBe(false);
  });

  it("rejects a MetaInformation entry from a different oletools script", () => {
    expect(isOlevbaResult(JSON.parse(doc([resultEntry()], { script_name: "olevba3" })))).toBe(false);
  });

  it("rejects a non-array root", () => {
    expect(isOlevbaResult({ hello: "world" })).toBe(false);
  });
});

describe("parseOlevbaResult — malformed input", () => {
  it("returns null for text that isn't valid JSON", () => {
    expect(parseOlevbaResult("not json at all")).toBeNull();
  });

  it("returns null for valid JSON that isn't an olevba document", () => {
    expect(parseOlevbaResult(JSON.stringify({ hello: "world" }))).toBeNull();
  });
});

describe("parseOlevbaResult — macro-free documents", () => {
  it("produces zero events for a document whose analysis is null, without counting it malformed", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: null })]))!;
    expect(r.events).toHaveLength(0);
    expect(r.malformedFindings).toBe(0);
    expect(r.total).toBe(1);
  });
});

describe("parseOlevbaResult — a single AutoExec finding", () => {
  it("maps to an Info-severity, undated finding event naming the entry point, never claiming the macro ran", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC] })]))!;
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    const block = e.canonical!.olevbaFinding!;
    expect(block.findingType).toBe("AutoExec");
    expect(block.keyword).toBe("AutoOpen");
    expect(block.descriptions).toEqual(["Runs when the Word document is opened"]);
    expect(block.occurrences).toBe(1);
    expect(block.documentPath).toBe("sample.doc");
    expect(e.description).toContain("never a claim the macro ran");
  });

  it("records the SAME mappingVersion on the canonical block and the producer metadata", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC] })]))!;
    const e = r.events[0];
    expect(e.canonical!.olevbaFinding!.mappingVersion).toBe("olevba-finding-v1");
    expect(e.canonical!.producer.mappingVersion).toBe(e.canonical!.olevbaFinding!.mappingVersion);
  });
});

describe("parseOlevbaResult — report identity", () => {
  it("gives two separate reports different aggKeys and different descriptions even with identical findings", () => {
    const r1 = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC] })]))!;
    const r2 = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC] })], { version: "0.60.3" }))!;
    expect(r1.events[0].aggKey).not.toBe(r2.events[0].aggKey);
    expect(r1.events[0].description).not.toBe(r2.events[0].description);
  });

  it("gives two result entries with the same file but different containers distinct aggKeys (no collision)", () => {
    const entries = [
      resultEntry({ file: "macro.doc", container: "outer1.zip", analysis: [AUTOEXEC] }),
      resultEntry({ file: "macro.doc", container: "outer2.zip", analysis: [AUTOEXEC] }),
    ];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.events).toHaveLength(2);
    const aggKeys = r.events.map((e) => e.aggKey);
    expect(new Set(aggKeys).size).toBe(2);
  });
});

describe("parseOlevbaResult — exact-string capability matching (Codex design review finding)", () => {
  it("does NOT treat a benign Suspicious description as a capability keyword, even with superficially similar wording", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC, BENIGN_SUSPICIOUS] })]))!;
    expect(r.events.some((e) => e.canonical?.olevbaCompoundLead)).toBe(false);
    // Both per-finding rows still exist, unaffected.
    expect(r.events.filter((e) => e.canonical?.olevbaFinding)).toHaveLength(2);
  });

  it("does NOT create a compound lead for a capability keyword alone, with no auto-run entry point", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [DOWNLOAD_SUSPICIOUS] })]))!;
    expect(r.events.some((e) => e.canonical?.olevbaCompoundLead)).toBe(false);
  });

  it("does NOT create a compound lead for an AutoExec entry point alone, with no capability keyword", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC] })]))!;
    expect(r.events.some((e) => e.canonical?.olevbaCompoundLead)).toBe(false);
  });
});

describe("parseOlevbaResult — the compound static-capability lead", () => {
  it("creates exactly ONE Low-severity compound lead when an auto-run entry point and a real capability keyword co-occur, and leaves the per-finding Info rows unchanged", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC, DOWNLOAD_SUSPICIOUS] })]))!;
    const leads = r.events.filter((e) => e.canonical?.olevbaCompoundLead);
    expect(leads).toHaveLength(1);
    expect(leads[0].severity).toBe("Low");
    const block = leads[0].canonical!.olevbaCompoundLead!;
    expect(block.autoExecKeywords).toEqual(["AutoOpen"]);
    expect(block.capabilityKeywords).toEqual(["URLDownloadToFile"]);
    expect(block.capabilityClasses).toEqual(["download"]);
    expect(r.events.filter((e) => e.canonical?.olevbaFinding).every((e) => e.severity === "Info")).toBe(true);
  });

  it("the compound lead's own description discloses it is co-occurrence, not a proven call", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [AUTOEXEC, DOWNLOAD_SUSPICIOUS] })]))!;
    const lead = r.events.find((e) => e.canonical?.olevbaCompoundLead)!;
    expect(lead.description).toContain("not a proven");
  });
});

describe("parseOlevbaResult — the VBA stomping lead", () => {
  it("creates a Low-severity stomping lead, distinct from and alongside the per-finding Info row", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [STOMPING] })]))!;
    const leads = r.events.filter((e) => e.canonical?.olevbaStompingLead);
    expect(leads).toHaveLength(1);
    expect(leads[0].severity).toBe("Low");
    const finding = r.events.find((e) => e.canonical?.olevbaFinding)!;
    expect(finding.severity).toBe("Info");
  });

  it("the stomping lead's own description discloses it is a lead, not a verdict", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [STOMPING] })]))!;
    const lead = r.events.find((e) => e.canonical?.olevbaStompingLead)!;
    expect(lead.description).toContain("not automatically malicious");
  });
});

describe("parseOlevbaResult — IOC category mapping", () => {
  it("maps a controlled IOC category directly to its SIEM IOC type, never through extractIocsFromText", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [IOC_URL] })]))!;
    expect(r.iocs).toHaveLength(1);
    expect(r.iocs[0]).toMatchObject({ type: "url", value: "http://evil.example/payload.exe" });
  });

  it("links the IOC's sourceAggKeys to the finding event that reported it", () => {
    const r = parseOlevbaResult(doc([resultEntry({ analysis: [IOC_URL] })]))!;
    expect(r.iocs[0].sourceAggKeys).toEqual([r.events[0].aggKey]);
  });

  it("falls back to extractIocsFromText for an IOC entry whose description names no controlled category", () => {
    const r = parseOlevbaResult(
      doc([
        resultEntry({ analysis: [{ type: "IOC", keyword: "203.0.113.9", description: "IPv4 address" }] }),
      ]),
    )!;
    expect(r.iocs.some((i) => i.type === "ip" && i.value === "203.0.113.9")).toBe(true);
  });
});

describe("parseOlevbaResult — bounded, deduped description variants", () => {
  it("keeps distinct description variants for the same (type, keyword) pair instead of collapsing to the last one seen", () => {
    const entries = [
      resultEntry({
        analysis: [
          { type: "Base64 String", keyword: "cmd.exe", description: "encoded string 'Y21kLmV4ZQ=='" },
          { type: "Base64 String", keyword: "cmd.exe", description: "encoded string 'Y21kLmV4ZQ==\\n'" },
        ],
      }),
    ];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.olevbaFinding!;
    expect(block.descriptions).toHaveLength(2);
    expect(block.occurrences).toBe(2);
  });

  it("dedupes byte-identical description repeats into one citation while still counting occurrences", () => {
    const entries = [resultEntry({ analysis: [AUTOEXEC, AUTOEXEC] })];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.olevbaFinding!;
    expect(block.occurrences).toBe(2);
    expect(block.descriptions).toHaveLength(1);
  });
});

describe("parseOlevbaResult — malformed findings and tool signals", () => {
  it("counts an analysis entry missing keyword/type as malformed, never crashes", () => {
    const entries = [resultEntry({ analysis: [{ type: "AutoExec" }, AUTOEXEC] })];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedFindings).toBe(1);
  });

  it("counts an analysis entry with an unrecognized findingType as malformed", () => {
    const entries = [
      resultEntry({ analysis: [{ type: "Form String", keyword: "x", description: "" }, AUTOEXEC] }),
    ];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedFindings).toBe(1);
  });

  it("counts a top-level error entry without crashing, disclosed via errorEntries", () => {
    const text = doc([
      resultEntry({ analysis: [AUTOEXEC] }),
      { type: "error", error: "failed to parse OLE stream" },
    ]);
    const r = parseOlevbaResult(text)!;
    expect(r.errorEntries).toBe(1);
  });

  it("captures a relevant tool warning message but ignores an unrelated informational one", () => {
    const text = doc([
      resultEntry({ analysis: [AUTOEXEC] }),
      { type: "msg", msg: "VBA parsing unsupported for this format" },
      { type: "msg", msg: "starting analysis" },
    ]);
    const r = parseOlevbaResult(text)!;
    expect(r.toolWarnings).toHaveLength(1);
    expect(r.toolWarnings[0]).toContain("unsupported");
  });
});

describe("parseOlevbaResult — result-entry volume bound", () => {
  it("discloses resultsTruncated once the number of result entries exceeds the per-report cap", () => {
    const entries = Array.from({ length: 501 }, (_, i) =>
      resultEntry({ file: `doc${i}.doc`, analysis: [AUTOEXEC] }),
    );
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.resultsTruncated).toBe(true);
    expect(r.total).toBe(500);
  });
});

describe("parseOlevbaResult — report-wide analysis-entry scan bound (Codex code review finding)", () => {
  it("stops scanning WITHIN a single oversized result entry's own analysis array, not only between entries", () => {
    const oversized = Array.from({ length: 50_100 }, (_, i) => ({
      type: "Base64 String",
      keyword: `k${i}`,
      description: "d",
    }));
    const entries = [resultEntry({ analysis: oversized })];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.analysisTruncated).toBe(true);
    // Distinct keywords stop appearing once the shared, report-wide budget is exhausted.
    expect(r.events.length).toBeLessThan(50_100);
  });
});

describe("parseOlevbaResult — malformed metadata never crashes the import (Codex code review finding)", () => {
  it("accepts a MetaInformation entry with no version field, leaving producerVersion empty rather than throwing", () => {
    const noVersionMeta = { type: "MetaInformation", script_name: "olevba" };
    const text = JSON.stringify([noVersionMeta, resultEntry({ analysis: [AUTOEXEC] })]);
    expect(() => parseOlevbaResult(text)).not.toThrow();
    const r = parseOlevbaResult(text)!;
    expect(r.events).toHaveLength(1);
    expect(r.events[0].canonical!.olevbaFinding!.producerVersion).toBe("");
  });

  it("excludes a result entry with an empty file path rather than crashing on an empty documentPath", () => {
    const entries = [resultEntry({ file: "", analysis: [AUTOEXEC] }), resultEntry({ analysis: [AUTOEXEC] })];
    expect(() => parseOlevbaResult(doc(entries))).not.toThrow();
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.total).toBe(1);
    expect(r.events).toHaveLength(1);
  });
});

describe("parseOlevbaResult — compound lead keyword length bound (Codex code review finding)", () => {
  it("clips an oversized AutoExec keyword instead of letting the canonical schema throw", () => {
    const longKeyword = "A".repeat(400);
    const entries = [
      resultEntry({
        analysis: [{ type: "AutoExec", keyword: longKeyword, description: "" }, DOWNLOAD_SUSPICIOUS],
      }),
    ];
    expect(() => parseOlevbaResult(doc(entries))).not.toThrow();
    const r = parseOlevbaResult(doc(entries))!;
    const lead = r.events.find((e) => e.canonical?.olevbaCompoundLead)!;
    expect(lead.canonical!.olevbaCompoundLead!.autoExecKeywords[0].length).toBeLessThanOrEqual(300);
  });
});

describe("parseOlevbaResult — IOC mapping robustness (Codex code review finding)", () => {
  it("finds a controlled category among several description citations, not only the first one seen", () => {
    const entries = [
      resultEntry({
        analysis: [
          { type: "IOC", keyword: "http://evil.example/payload.exe", description: "some other citation" },
          { type: "IOC", keyword: "http://evil.example/payload.exe", description: "URL" },
        ],
      }),
    ];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.iocs).toHaveLength(1);
    expect(r.iocs[0].type).toBe("url");
  });

  it("bounds a directly-mapped IOC value at the same field length every other olevba field respects", () => {
    const longUrl = `http://evil.example/${"a".repeat(400)}`;
    const entries = [resultEntry({ analysis: [{ type: "IOC", keyword: longUrl, description: "URL" }] })];
    const r = parseOlevbaResult(doc(entries))!;
    expect(r.iocs[0].value.length).toBeLessThanOrEqual(300);
  });
});
