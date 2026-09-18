import { describe, it, expect } from "vitest";
import {
  isBulkExtractorCarvedFeatureFile,
  parseBulkExtractorCarved,
  MAX_DISTINCT_VALUES,
} from "../../src/analysis/bulkExtractorCarvedImport.js";
import { isBulkExtractorUrlFeatureFile } from "../../src/analysis/bulkExtractorUrlImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";

// Line shape verified against bulk_extractor 2.x's own be20_api feature_recorder.cpp carve():
//   pos0 \t carved_relative_path \t <fileobject><filename>…</filename><filesize>N</filesize><hashdigest type='md5'>hex</hashdigest></fileobject>
// A cached re-carve writes feature "<CACHED>" (feature_recorder.h:229) and omits <filename>.
const MD5_A = "9e107d9d372bb6826bd81d3542a419d6";
const MD5_B = "e4d909c290d0fb1ca068ffaddf22cbd0";
const SHA256_A = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

function ctx(o: { filename?: string; filesize: number; algo?: string; hex: string }): string {
  return (
    `<fileobject>` +
    (o.filename ? `<filename>${o.filename}</filename>` : "") +
    `<filesize>${o.filesize}</filesize>` +
    `<hashdigest type='${o.algo ?? "md5"}'>${o.hex}</hashdigest></fileobject>`
  );
}

function carvedRow(
  offset: string,
  path: string,
  o: { filesize: number; algo?: string; hex: string },
): string {
  return `${offset}\t${path}\t${ctx({ filename: path, ...o })}`;
}
function cachedRow(offset: string, o: { filesize: number; algo?: string; hex: string }): string {
  return `${offset}\t<CACHED>\t${ctx(o)}`;
}

function feature(
  recorder: string,
  rows: string[],
  opts: { filename?: boolean; version?: boolean } = {},
): string {
  const head = [
    "# BANNER FILE NOT PROVIDED (-b option)",
    ...(opts.version === false ? [] : ["# BULK_EXTRACTOR-Version: 2.0.3"]),
    `# Feature-Recorder: ${recorder}`,
    ...(opts.filename === false ? [] : ["# Filename: /evidence/laptop.E01"]),
    "# Feature-File-Version: 1.1",
  ];
  return [...head, ...rows].join("\n") + "\n";
}

const JPEG_ONE = feature("jpeg", [
  carvedRow("1048576", "jpeg/000/1048576.jpg", { filesize: 48213, hex: MD5_A }),
]);

describe("isBulkExtractorCarvedFeatureFile — structural detection with a quorum", () => {
  it("matches a real-shaped jpeg carved feature file", () => {
    expect(isBulkExtractorCarvedFeatureFile(JPEG_ONE)).toBe(true);
  });

  it("matches any recorder name, including one that does not exist yet (structure, not a name list)", () => {
    const f = feature("future_carved", [
      carvedRow("5", "future_carved/000/5.bin", { filesize: 9, hex: MD5_A }),
    ]);
    expect(isBulkExtractorCarvedFeatureFile(f)).toBe(true);
    expect(parseBulkExtractorCarved(f)!.recorder).toBe("future_carved");
  });

  it("does NOT match a url.txt whose contexts are raw bytes", () => {
    const url = feature("url", ["4096\thttp://example.com/a\tNUL bytes http://example.com/a NUL"]);
    expect(isBulkExtractorCarvedFeatureFile(url)).toBe(false);
    expect(isBulkExtractorUrlFeatureFile(url)).toBe(true);
  });

  it("does NOT match a crafted url.txt that plants one fileobject-shaped context — the quorum needs EVERY row", () => {
    const hybrid = feature("url", [
      `4096\t<fileobject>\t${ctx({ filename: "x", filesize: 1, hex: MD5_A })}`,
      "8192\thttp://example.com/b\traw context bytes",
    ]);
    expect(isBulkExtractorCarvedFeatureFile(hybrid)).toBe(false);
    expect(detectImportKind("url.txt", hybrid)).toBe("bulkextractorurl");
  });

  it("rejects a fileobject context with no hashdigest child", () => {
    const f = feature("jpeg", [
      "1\tjpeg/000/1.jpg\t<fileobject><filename>jpeg/000/1.jpg</filename><filesize>5</filesize></fileobject>",
    ]);
    expect(isBulkExtractorCarvedFeatureFile(f)).toBe(false);
  });

  it("rejects a missing BULK_EXTRACTOR-Version anchor and a missing Feature-Recorder anchor", () => {
    expect(
      isBulkExtractorCarvedFeatureFile(feature("jpeg", [JPEG_ONE.split("\n")[5]], { version: false })),
    ).toBe(false);
    const noRecorder = JPEG_ONE.replace(/^# Feature-Recorder: jpeg\n/m, "");
    expect(isBulkExtractorCarvedFeatureFile(noRecorder)).toBe(false);
  });

  it("rejects a headers-only file (a genuine 'carved nothing' has no row to match — a disclosed limitation)", () => {
    expect(isBulkExtractorCarvedFeatureFile(feature("jpeg", []))).toBe(false);
  });

  it("importDetect returns bulkextractorcarved, ahead of the url detector", () => {
    expect(detectImportKind("jpeg.txt", JPEG_ONE)).toBe("bulkextractorcarved");
  });
});

describe("parseBulkExtractorCarved — one carved object", () => {
  it("maps to an Info, undated carved-file event carrying the tool's own path/size/digest and both disclosure literals", () => {
    const r = parseBulkExtractorCarved(JPEG_ONE)!;
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    expect(e.sources).toEqual(["bulk_extractor"]);
    const b = e.canonical!.recoveredFragment!;
    expect(b.artifactClass).toBe("carved-file");
    if (b.artifactClass !== "carved-file") return;
    expect(b.recorder).toBe("jpeg");
    expect(b.producerVersion).toBe("2.0.3");
    expect(b.value).toBe("jpeg/000/1048576.jpg");
    expect(b.hash).toEqual({ algorithm: "md5", hex: MD5_A });
    expect(b.filesize).toBe(48213);
    expect(b.sourceMedia).toBe("/evidence/laptop.E01");
    expect(b.hashIocPromoted).toBe(true);
    expect(b.degenerate).toBe(false);
    expect(b.toolFlag).toBe("none");
    expect(b.allCachedAnomaly).toBe(false);
    expect(b.completeness).toContain("not written as structured data");
    expect(b.orderingAnomaly).toBe(false);
    expect(b.structuralValidation).toContain("acceptance gate");
    expect(b.hashScope).toContain("whole file");
    expect(b.citations[0]).toEqual({
      rawOffset: "1048576",
      parsed: true,
      rootOffset: 1048576,
      path: [],
      context: expect.any(String),
    });
    expect(e.description).toContain("completeness not written by the tool as structured data");
    expect(e.description).toContain("not proof it existed as a named filesystem entry");
    expect(e.description).toContain("[undated:");
  });

  it("promotes the digest to a case hash IOC linked to this event's aggKey", () => {
    const r = parseBulkExtractorCarved(JPEG_ONE)!;
    const ioc = r.iocs.find((i) => i.type === "hash");
    expect(ioc?.value).toBe(MD5_A);
    expect(ioc?.sourceAggKeys).toEqual([r.events[0].aggKey]);
  });

  it("parses a decode-chain forensic path into hops and names it in the description", () => {
    const f = feature("zip_carved", [
      carvedRow("70000-ZIP-0", "zip_carved/000/70000-ZIP-0.docx", { filesize: 1200, hex: MD5_B }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.citations[0]).toMatchObject({
      parsed: true,
      rootOffset: 70000,
      path: [{ method: "ZIP", offset: 0 }],
    });
    expect(r.events[0].description).toContain("via ZIP decode at offset 70000");
  });

  it("keeps an unparseable offset verbatim as an unparsed citation, never dropped", () => {
    const f = feature("jpeg", [carvedRow("weird-offset", "jpeg/000/x.jpg", { filesize: 10, hex: MD5_A })]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.citations[0]).toMatchObject({ rawOffset: "weird-offset", parsed: false });
  });

  it("honors `# Filename:` only from the header block, never from a data row", () => {
    const f =
      feature("jpeg", [carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, hex: MD5_A })], { filename: false }) +
      "# Filename: /smuggled/from/a/row.E01\n";
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.sourceMedia).toBeUndefined();
  });
});

describe("parseBulkExtractorCarved — <CACHED> folding (the tool's own dedup)", () => {
  it("folds a cached re-carve of the same digest into ONE event: occurrences 2, cachedOccurrences 1, one IOC", () => {
    const f = feature("jpeg", [
      carvedRow("100", "jpeg/000/100.jpg", { filesize: 500, hex: MD5_A }),
      cachedRow("9000", { filesize: 500, hex: MD5_A }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.events).toHaveLength(1);
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.occurrences).toBe(2);
    expect(b.cachedOccurrences).toBe(1);
    expect(b.citations).toHaveLength(2); // both offsets retained as distinct citations
    expect(b.value).toBe("jpeg/000/100.jpg");
    expect(r.iocs.filter((i) => i.type === "hash")).toHaveLength(1);
    expect(r.events[0].description).toContain("1 reported by the tool as an already-carved duplicate");
  });

  it("recognizes a cached row by filename-absence alone, even if the feature literal differs", () => {
    const f = feature("jpeg", [
      carvedRow("100", "jpeg/000/100.jpg", { filesize: 500, hex: MD5_A }),
      `9000\tsomething-else\t${ctx({ filesize: 500, hex: MD5_A })}`,
    ]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.cachedOccurrences).toBe(1);
  });

  it("takes value and filesize from the FIRST non-cached row when a cached row reports a different size", () => {
    const f = feature("jpeg", [
      cachedRow("5", { filesize: 999, hex: MD5_A }),
      carvedRow("100", "jpeg/000/100.jpg", { filesize: 500, hex: MD5_A }),
    ]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.value).toBe("jpeg/000/100.jpg");
    expect(b.filesize).toBe(500);
    expect(b.allCachedAnomaly).toBe(false);
  });

  it("a collision-shaped second sighting (same digest, different offset, <CACHED>) is presented as a duplicate — disclosed by dedupBasis, never claimed as byte-verified", () => {
    const f = feature("jpeg", [
      carvedRow("100", "jpeg/000/100.jpg", { filesize: 500, hex: MD5_A }),
      cachedRow("777777", { filesize: 501, hex: MD5_A }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.events).toHaveLength(1);
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.dedupBasis).toContain("bytes are never re-compared");
  });

  it("flags an all-cached digest as an anomaly with an importer-synthesized value, still imported", () => {
    const f = feature("jpeg", [
      cachedRow("5", { filesize: 10, hex: MD5_A }),
      cachedRow("6", { filesize: 10, hex: MD5_A }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.events).toHaveLength(1);
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.allCachedAnomaly).toBe(true);
    expect(b.value).toBe(`hash:md5:${MD5_A}`);
    expect(b.filesize).toBeUndefined();
    expect(r.events[0].description).toContain("importer-synthesized");
    expect(r.events[0].description).toContain("object size not read (no first-sighting row)");
    expect(r.events[0].description).not.toContain("exceeds the representable range");
    expect(r.events[0].description).not.toContain("zero-byte");
  });

  it("gives two DIFFERENT digests two events and two IOCs", () => {
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, hex: MD5_A }),
      carvedRow("2", "jpeg/000/2.jpg", { filesize: 20, hex: MD5_B }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.events).toHaveLength(2);
    expect(
      r.iocs
        .filter((i) => i.type === "hash")
        .map((i) => i.value)
        .sort(),
    ).toEqual([MD5_A, MD5_B].sort());
  });

  it("the same digest in two recorders' files yields two events (per uploaded report) sharing one source label, so it can never self-corroborate", () => {
    const a = parseBulkExtractorCarved(
      feature("jpeg", [carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, hex: MD5_A })]),
    )!;
    const b = parseBulkExtractorCarved(
      feature("zip_carved", [carvedRow("2", "zip_carved/000/2.jpg", { filesize: 10, hex: MD5_A })]),
    )!;
    expect(a.events[0].aggKey).not.toBe(b.events[0].aggKey);
    expect(a.events[0].sources).toEqual(b.events[0].sources); // iocCorroboration counts DISTINCT source labels
  });
});

describe("parseBulkExtractorCarved — digest promotion guards", () => {
  it("promotes sha256 with a matching hex length", () => {
    const f = feature("winpe_carved", [
      carvedRow("1", "winpe_carved/000/1.winpe", { filesize: 4096, algo: "sha256", hex: SHA256_A }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.iocs.find((i) => i.type === "hash")?.value).toBe(SHA256_A);
    expect(r.unpromotedValues).toBe(0);
  });

  it("normalizes the tool's own algorithm spellings (SHA-1 → sha1) before the length check", () => {
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, algo: "SHA-1", hex: "a".repeat(40) }),
    ]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.hash.algorithm).toBe("sha1");
    expect(b.hashIocPromoted).toBe(true);
  });

  it("keeps an unrecognized algorithm in the record but promotes nothing", () => {
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, algo: "crc32", hex: "deadbeef" }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.hash).toEqual({ algorithm: "crc32", hex: "deadbeef" });
    expect(b.hashIocPromoted).toBe(false);
    expect(r.iocs).toHaveLength(0);
    expect(r.unpromotedValues).toBe(1);
    expect(r.events[0].description).toContain("digest algorithm not promotable");
  });

  it("a known algorithm with the WRONG hex length is kept but never promoted", () => {
    const f = feature("jpeg", [carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, algo: "md5", hex: "abcd" })]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.iocs).toHaveLength(0);
  });

  it("never promotes a zero-byte object, and flags it degenerate", () => {
    const f = feature("jpeg", [carvedRow("1", "jpeg/000/1.jpg", { filesize: 0, hex: MD5_A })]);
    const r = parseBulkExtractorCarved(f)!;
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.degenerate).toBe(true);
    expect(b.hashIocPromoted).toBe(false);
    expect(r.iocs).toHaveLength(0);
    expect(r.events[0].description).toContain("zero-byte object");
  });

  it("a 20-digit <filesize> above MAX_SAFE_INTEGER: filesize dropped, degenerate, no IOC, and the description names the over-range size — never 'not reported'", () => {
    // 8 PiB-scale: bulk_extractor cannot carve this from a real image, so the sentence must point
    // at the reported value, not hedge about an absent one (an absent <filesize> is a malformed row).
    const oversized = "99999999999999999999"; // 20 digits, passes the row regex, fails isSafeInteger
    const f = feature("jpeg", [
      `1\tjpeg/000/1.jpg\t<fileobject><filename>jpeg/000/1.jpg</filename><filesize>${oversized}</filesize><hashdigest type='md5'>${MD5_A}</hashdigest></fileobject>`,
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedRows).toBe(0);
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.filesize).toBeUndefined();
    expect(b.degenerate).toBe(true);
    expect(b.hashIocPromoted).toBe(false);
    expect(r.iocs).toHaveLength(0);
    expect(r.events[0].description).toContain(
      "reported object size exceeds the representable range, digest not promoted",
    );
    expect(r.events[0].description).not.toContain("not reported");
    expect(r.events[0].description).not.toContain("zero-byte");
  });

  it("never promotes the algorithm's empty-input digest even with a nonzero reported size", () => {
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 77, hex: "d41d8cd98f00b204e9800998ecf8427e" }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.iocs).toHaveLength(0);
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.degenerate).toBe(true);
  });

  it("every event carries the md5-collision caveat literal", () => {
    const b = parseBulkExtractorCarved(JPEG_ONE)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.hashPromotionCaveat).toContain("collision-prone");
  });
});

describe("parseBulkExtractorCarved — the tool's own verdict signals and hash scope", () => {
  it("reads an NTFS recorder's _corrupted filename suffix as toolFlag corrupted", () => {
    const f = feature("ntfsmft_carved", [
      carvedRow("4096", "ntfsmft_carved/000/4096.mft_corrupted", { filesize: 1024, hex: MD5_A }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.toolFlag).toBe("corrupted");
    expect(r.events[0].description).toContain("flagged this object corrupted");
  });

  it("does NOT read a _corrupted suffix as the tool's verdict on a recorder that never writes one (jpeg)", () => {
    const f = feature("jpeg", [carvedRow("1", "jpeg/000/1.jpg_corrupted", { filesize: 10, hex: MD5_A })]);
    const r = parseBulkExtractorCarved(f)!;
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.toolFlag).toBe("none");
    expect(r.events[0].description).not.toContain("flagged this object corrupted");
  });

  it("reads evtx's orphan-record suffix", () => {
    const f = feature("evtx_carved", [
      carvedRow("9", "evtx_carved/000/9.evtx_orphan_record", { filesize: 300, hex: MD5_A }),
    ]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.toolFlag).toBe("orphan-record");
  });

  it("states hashScope per recorder: whole file for jpeg, data-only for the header-prepending evtx, not-stated for an unknown recorder", () => {
    const scope = (rec: string) => {
      const b = parseBulkExtractorCarved(
        feature(rec, [carvedRow("1", `${rec}/000/1.x`, { filesize: 5, hex: MD5_A })]),
      )!.events[0].canonical!.recoveredFragment!;
      return b.artifactClass === "carved-file" ? b.hashScope : "";
    };
    expect(scope("jpeg")).toContain("whole file");
    expect(scope("evtx_carved")).toContain("data buffer only");
    expect(scope("future_carved")).toContain("not stated");
    // recorder names that exist but whose carve() call was never located in source never get the strong claim
    expect(scope("unrar_carved")).toContain("not stated");
    expect(scope("utmp_carved")).toContain("not stated");
  });
});

describe("parseBulkExtractorCarved — malformed rows are counted, never stored, never crash", () => {
  it("counts a 2-field row, a 4-field row, an empty feature, a non-hex digest, an unterminated fileobject, and an oversized offset (behind a clean detection quorum)", () => {
    const lead = Array.from({ length: 8 }, (_, i) =>
      carvedRow(String(100 + i), `jpeg/000/${100 + i}.jpg`, {
        filesize: 10,
        hex: (i + 1).toString(16).padStart(32, "0"),
      }),
    );
    const f = feature("jpeg", [
      ...lead,
      "1\tjpeg/000/1.jpg",
      `2\tjpeg/000/2.jpg\t${ctx({ filename: "jpeg/000/2.jpg", filesize: 1, hex: MD5_A })}\textra`,
      `3\t\t${ctx({ filename: "jpeg/000/3.jpg", filesize: 1, hex: MD5_A })}`,
      `4\tjpeg/000/4.jpg\t<fileobject><filename>jpeg/000/4.jpg</filename><filesize>1</filesize><hashdigest type='md5'>zz</hashdigest></fileobject>`,
      `5\tjpeg/000/5.jpg\t<fileobject><filename>jpeg/000/5.jpg</filename><filesize>1</filesize><hashdigest type='md5'>${MD5_A}</hashdigest>`,
      `${"9".repeat(10_001)}\tjpeg/000/6.jpg\t${ctx({ filename: "jpeg/000/6.jpg", filesize: 1, hex: MD5_A })}`,
      carvedRow("7", "jpeg/000/7.jpg", { filesize: 1, hex: MD5_B }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.events).toHaveLength(9);
    expect(r.malformedRows).toBe(6);
    expect(r.total).toBe(15);
  });

  it("a malformed row INSIDE the detection quorum means the upload is not recognized as a carved feature file at all", () => {
    const f = feature("jpeg", [
      "1\tjpeg/000/1.jpg",
      carvedRow("2", "jpeg/000/2.jpg", { filesize: 1, hex: MD5_A }),
    ]);
    expect(parseBulkExtractorCarved(f)).toBeNull();
  });

  it("rejects a non-cached row whose feature disagrees with its <filename> child (carve() writes the same variable to both)", () => {
    const f = feature("jpeg", [
      carvedRow("2", "jpeg/000/2.jpg", { filesize: 1, hex: MD5_B }),
      `1\tjpeg/000/REAL.jpg\t${ctx({ filename: "jpeg/000/OTHER.jpg", filesize: 1, hex: MD5_A })}`,
    ]);
    const r = parseBulkExtractorCarved(f)!;
    expect(r.malformedRows).toBe(1);
    expect(r.events).toHaveLength(1);
  });

  it("returns null for text that is not a carved feature file", () => {
    expect(parseBulkExtractorCarved("not a feature file")).toBeNull();
    expect(parseBulkExtractorCarved(feature("url", ["1\thttp://x\traw"]))).toBeNull();
  });
});

describe("parseBulkExtractorCarved — caps", () => {
  it("discloses distinct digests beyond MAX_DISTINCT_VALUES via notCitedValues, counted once per digest", () => {
    const rows = Array.from({ length: MAX_DISTINCT_VALUES + 3 }, (_, i) =>
      carvedRow(String(i), `jpeg/000/${i}.jpg`, { filesize: 10, hex: i.toString(16).padStart(32, "0") }),
    );
    // the 3 overflow digests each appear twice — still counted once each
    const over = rows.slice(-3);
    const r = parseBulkExtractorCarved(feature("jpeg", [...rows, ...over]))!;
    expect(r.events.length).toBeLessThanOrEqual(MAX_DISTINCT_VALUES);
    expect(r.notCitedValues).toBe(3);
  });

  it("clips an oversized carved path and discloses valueTruncated", () => {
    const longPath = "jpeg/000/" + "a".repeat(3000) + ".jpg";
    const f = feature("jpeg", [carvedRow("1", longPath, { filesize: 10, hex: MD5_A })]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.valueTruncated).toBe(true);
    expect(b.value.length).toBeLessThanOrEqual(2000);
  });
});

describe("importBulkExtractorCarved — the ingest wrapper, end to end through a real state store", () => {
  it("persists the carved-file events and the hash IOC linked to them, sourced bulk_extractor", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-carved-"));
    const caseStore = new CaseStore(root);
    await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
    const stateStore = new StateStore(caseStore);
    const pipeline = new AnalysisPipeline({
      provider: new MockProvider("mock", "{}"),
      stateStore,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, hex: MD5_A }),
      cachedRow("2", { filesize: 10, hex: MD5_A }),
      carvedRow("3", "jpeg/000/3.jpg", { filesize: 0, hex: MD5_B }), // degenerate: never an IOC
    ]);
    const state = await pipeline.importBulkExtractorCarved("c1", f, {
      label: "jpeg.txt",
      idPrefix: "bx",
      importedAt: "2026-09-18T12:00:00.000Z",
    });
    const carved = state.forensicTimeline.filter(
      (e) => e.canonical?.recoveredFragment?.artifactClass === "carved-file",
    );
    expect(carved).toHaveLength(2);
    expect(carved.every((e) => e.sources?.includes("bulk_extractor"))).toBe(true);
    const hashes = state.iocs.filter((i) => i.type === "hash");
    expect(hashes.map((i) => i.value)).toEqual([MD5_A]);
    expect(hashes[0].extractedFrom).toHaveLength(1);
    expect(carved.map((e) => e.id)).toContain(hashes[0].extractedFrom![0]);
  });
});

describe("parseBulkExtractorCarved — ordering/shape anomalies the tool never writes (Ollama code review)", () => {
  it("a cache marker BEFORE the digest's real row: flagged, and the real row's offset still leads the citations", () => {
    const f = feature("jpeg", [
      cachedRow("5", { filesize: 10, hex: MD5_A }),
      carvedRow("100", "jpeg/000/100.jpg", { filesize: 10, hex: MD5_A }),
    ]);
    const r = parseBulkExtractorCarved(f)!;
    const b = r.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass !== "carved-file") return;
    expect(b.orderingAnomaly).toBe(true);
    expect(b.citations[0].rawOffset).toBe("100");
    expect(r.events[0].description).toContain("at image offset 100");
    expect(r.events[0].description).toContain("row order/shape for this digest is one the tool never writes");
  });

  it("two non-cached rows for one digest: flagged (the carve cache blocks a second write in a pristine run)", () => {
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, hex: MD5_A }),
      carvedRow("2", "jpeg/000/2.jpg", { filesize: 10, hex: MD5_A }),
    ]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.orderingAnomaly).toBe(true);
  });

  it("a row folded as cached by filename-absence alone (feature is not the <CACHED> literal): flagged", () => {
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, hex: MD5_A }),
      `2\tnot-the-literal\t${ctx({ filesize: 10, hex: MD5_A })}`,
    ]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.orderingAnomaly).toBe(true);
  });

  it("the pristine shape — one real row first, then cache markers — is NOT flagged", () => {
    const f = feature("jpeg", [
      carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, hex: MD5_A }),
      cachedRow("2", { filesize: 10, hex: MD5_A }),
      cachedRow("3", { filesize: 10, hex: MD5_A }),
    ]);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.orderingAnomaly).toBe(false);
  });
});

describe("parseBulkExtractorCarved — remaining code-review pins", () => {
  it("bounds sourceMedia from an oversized # Filename: header", () => {
    const long = "/evidence/" + "x".repeat(3000) + ".E01";
    const f = JPEG_ONE.replace("# Filename: /evidence/laptop.E01", `# Filename: ${long}`);
    const b = parseBulkExtractorCarved(f)!.events[0].canonical!.recoveredFragment!;
    if (b.artifactClass === "carved-file") expect(b.sourceMedia!.length).toBeLessThanOrEqual(2000);
  });

  it("tolerates an enclosing quote PAIR on the context but not a lone quote", () => {
    const paired = feature("jpeg", [
      `1\tjpeg/000/1.jpg\t"${ctx({ filename: "jpeg/000/1.jpg", filesize: 10, hex: MD5_A })}"`,
    ]);
    expect(parseBulkExtractorCarved(paired)!.events).toHaveLength(1);
    const lone = feature("jpeg", [
      `1\tjpeg/000/1.jpg\t"${ctx({ filename: "jpeg/000/1.jpg", filesize: 10, hex: MD5_A })}`,
    ]);
    expect(isBulkExtractorCarvedFeatureFile(lone)).toBe(false);
  });

  it("a wrong-length digest for a known algorithm says so, not 'algorithm not promotable'", () => {
    const f = feature("jpeg", [carvedRow("1", "jpeg/000/1.jpg", { filesize: 10, algo: "md5", hex: "abcd" })]);
    expect(parseBulkExtractorCarved(f)!.events[0].description).toContain(
      "digest length does not match its algorithm",
    );
  });
});
