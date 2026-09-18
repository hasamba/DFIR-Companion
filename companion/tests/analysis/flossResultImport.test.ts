import { describe, it, expect } from "vitest";
import { parseFlossResult, isFlossResult } from "../../src/analysis/flossResultImport.js";

// Field names verified live against FLOSS's own results.py dataclasses (mandiant/flare-floss on
// GitHub) and a real populated sample (smart_strings repo's malware-set_Virus.Win32.CTZA.json).
const METADATA = {
  file_path: "/samples/malware.exe",
  md5: "5e8ff9bf55ba3508199d22e984129be6",
  sha1: "8151325dcdbae9e0ff95f9f9658432dbedfdb209",
  sha256: "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
  version: "v2.2.0-0-g783dd8f",
  imagebase: 4194304,
  min_length: 4,
  runtime: { total: 1.2 },
  language: "",
  language_version: "",
  language_selected: "",
};

const DECODED_ENTRY = {
  address: 4198400,
  address_type: "absolute",
  string: "cmd.exe /c whoami",
  encoding: "ASCII",
  decoded_at: 4199118,
  decoding_routine: 4198722,
};

const STACK_ENTRY = {
  function: 4198400,
  string: "SbieDll.dll",
  encoding: "ASCII",
  program_counter: 4199118,
  stack_pointer: 6684672,
  original_stack_pointer: 6684700,
  offset: 12,
  frame_offset: -8,
};

// language_strings/language_strings_missed share FLOSS's own flat StaticString shape (string,
// offset, encoding) — no decoding-routine or stack-frame citation, verified against results.py.
const LANGUAGE_ENTRY = { string: "runtime.gopanic", offset: 4096, encoding: "ASCII" };

function floss(overrides: {
  metadata?: Partial<typeof METADATA>;
  decoded?: unknown[];
  stack?: unknown[];
  tight?: unknown[];
  language?: unknown[];
  languageMissed?: unknown[];
  static_?: unknown[];
}): string {
  return JSON.stringify({
    metadata: { ...METADATA, ...(overrides.metadata ?? {}) },
    analysis: {},
    strings: {
      decoded_strings: overrides.decoded ?? [],
      stack_strings: overrides.stack ?? [],
      tight_strings: overrides.tight ?? [],
      language_strings: overrides.language ?? [],
      language_strings_missed: overrides.languageMissed ?? [],
      static_strings: overrides.static_ ?? [],
    },
  });
}

describe("isFlossResult", () => {
  it("recognizes a real FLOSS results document", () => {
    expect(isFlossResult(JSON.parse(floss({ decoded: [DECODED_ENTRY] })))).toBe(true);
  });

  it("recognizes an older FLOSS version-string format (0.1.0, not v2.2.0-0-g...)", () => {
    expect(isFlossResult(JSON.parse(floss({ metadata: { version: "0.1.0" } })))).toBe(true);
  });

  it("rejects an object with metadata but no strings sibling", () => {
    expect(isFlossResult({ metadata: METADATA })).toBe(false);
  });

  it("rejects an object with strings but no metadata sibling", () => {
    expect(isFlossResult({ strings: { decoded_strings: [] } })).toBe(false);
  });

  it("rejects a blank version string", () => {
    expect(isFlossResult(JSON.parse(floss({ metadata: { version: "" } })))).toBe(false);
  });

  it("rejects a missing file_path", () => {
    const bad = JSON.parse(floss({}));
    delete bad.metadata.file_path;
    expect(isFlossResult(bad)).toBe(false);
  });

  it("accepts a static-only upload (no decoded/stack/tight) as a real match", () => {
    expect(
      isFlossResult(JSON.parse(floss({ static_: [{ string: "CODE", offset: 1, encoding: "ASCII" }] }))),
    ).toBe(true);
  });

  it("rejects a plain unrelated JSON object", () => {
    expect(isFlossResult({ hello: "world" })).toBe(false);
  });
});

describe("parseFlossResult — a decoded string", () => {
  it("maps to an Info-severity, undated decoded-string event with its own citation shape", () => {
    const r = parseFlossResult(floss({ decoded: [DECODED_ENTRY] }));
    expect(r).not.toBeNull();
    expect(r!.events).toHaveLength(1);
    const e = r!.events[0];
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("");
    expect(e.canonical?.time?.observed).toBe("");
    const block = e.canonical!.decodedString!;
    expect(block.kind).toBe("decoded");
    expect(block.value).toBe("cmd.exe /c whoami");
    if (block.kind === "decoded") {
      expect(block.citations[0]).toEqual({
        address: 4198400,
        addressType: "absolute",
        encoding: "ASCII",
        decodedAt: 4199118,
        decodingRoutine: 4198722,
      });
    }
    expect(block.producerVersion).toBe("v2.2.0-0-g783dd8f");
    expect(e.description).toContain("not proof of network contact or capability use");
  });
});

describe("parseFlossResult — stack/tight strings", () => {
  it("maps a stack string with its own frame-context citation, including a negative frameOffset", () => {
    const r = parseFlossResult(floss({ stack: [STACK_ENTRY] }))!;
    const block = r.events[0].canonical!.decodedString!;
    expect(block.kind).toBe("stack");
    if (block.kind === "stack" || block.kind === "tight") {
      expect(block.citations[0]).toEqual({
        functionAddress: 4198400,
        encoding: "ASCII",
        programCounter: 4199118,
        stackPointer: 6684672,
        originalStackPointer: 6684700,
        offset: 12,
        frameOffset: -8,
      });
    }
  });

  it("records the SAME mappingVersion on the canonical block and the producer metadata for a tight string (Codex code review finding — these disagreed before the fix)", () => {
    const r = parseFlossResult(floss({ tight: [STACK_ENTRY] }))!;
    const e = r.events[0];
    const block = e.canonical!.decodedString!;
    expect(block.mappingVersion).toBe("floss-stack-v1");
    expect(e.canonical!.producer.mappingVersion).toBe(block.mappingVersion);
  });

  it("maps a tight string the same way as a stack string, distinct kind", () => {
    const r = parseFlossResult(floss({ tight: [STACK_ENTRY] }))!;
    expect(r.events[0].canonical!.decodedString!.kind).toBe("tight");
  });
});

describe("parseFlossResult — sample hash: validated, normalized, all registered as IOCs", () => {
  it("lowercases and validates every hash, sets hashUnavailable false", () => {
    const r = parseFlossResult(floss({ decoded: [DECODED_ENTRY] }))!;
    const block = r.events[0].canonical!.decodedString!;
    expect(block.sampleHash).toEqual({
      md5: METADATA.md5.toLowerCase(),
      sha1: METADATA.sha1.toLowerCase(),
      sha256: METADATA.sha256.toLowerCase(),
      hashUnavailable: false,
    });
  });

  it("registers every valid hash as its own case IOC, not just the strongest one", () => {
    const r = parseFlossResult(floss({ decoded: [DECODED_ENTRY] }))!;
    const hashIocs = r.iocs.filter((i) => i.type === "hash").map((i) => i.value);
    expect(hashIocs).toContain(METADATA.md5.toLowerCase());
    expect(hashIocs).toContain(METADATA.sha1.toLowerCase());
    expect(hashIocs).toContain(METADATA.sha256.toLowerCase());
  });

  it("links a sample-hash IOC to EVERY event this report produced, not just one", () => {
    const other = { ...DECODED_ENTRY, string: "a second, different decoded string", address: 1 };
    const r = parseFlossResult(floss({ decoded: [DECODED_ENTRY, other] }))!;
    expect(r.events).toHaveLength(2);
    const hashIoc = r.iocs.find((i) => i.type === "hash" && i.value === METADATA.sha256.toLowerCase());
    expect(hashIoc?.sourceAggKeys).toHaveLength(2);
    expect(new Set(hashIoc?.sourceAggKeys)).toEqual(new Set(r.events.map((e) => e.aggKey)));
  });

  it("treats a malformed hash field as absent, never silently coerced", () => {
    const r = parseFlossResult(floss({ metadata: { md5: "not-a-real-hash" }, decoded: [DECODED_ENTRY] }))!;
    const block = r.events[0].canonical!.decodedString!;
    expect(block.sampleHash.md5).toBeUndefined();
  });

  it("sets hashUnavailable when none of the three hashes validate, and still imports (report-fingerprint identity alone)", () => {
    const r = parseFlossResult(
      floss({ metadata: { md5: "", sha1: "", sha256: "" }, decoded: [DECODED_ENTRY] }),
    )!;
    const block = r.events[0].canonical!.decodedString!;
    expect(block.sampleHash.hashUnavailable).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(false);
  });
});

describe("parseFlossResult — report identity vs sample identity (Codex design review finding #2)", () => {
  it("gives two SEPARATE reports of the same sample different aggKeys and different descriptions", () => {
    const r1 = parseFlossResult(floss({ decoded: [DECODED_ENTRY] }))!;
    const r2 = parseFlossResult(floss({ decoded: [DECODED_ENTRY], metadata: { imagebase: 999 } }))!;
    expect(r1.events[0].aggKey).not.toBe(r2.events[0].aggKey);
    expect(r1.events[0].description).not.toBe(r2.events[0].description);
  });
});

describe("parseFlossResult — duplicate vs distinct occurrences (Codex design review finding #3)", () => {
  it("dedupes byte-identical occurrences (same value AND same citation fields) into one citation", () => {
    const r = parseFlossResult(floss({ decoded: [DECODED_ENTRY, { ...DECODED_ENTRY }] }))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.decodedString!;
    expect(block.occurrences).toBe(2);
    expect(block.citations).toHaveLength(1);
  });

  it("keeps two occurrences with the SAME string value but a DIFFERENT decoding routine as distinct citations", () => {
    const other = { ...DECODED_ENTRY, decoding_routine: 9999999 };
    const r = parseFlossResult(floss({ decoded: [DECODED_ENTRY, other] }))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.decodedString!;
    expect(block.occurrences).toBe(2);
    expect(block.citations).toHaveLength(2);
    expect(block.notCited).toBe(0);
  });

  it("caps citations at RECOVERY_CITATIONS_MAX and discloses overflow via notCited", () => {
    const many = Array.from({ length: 70 }, (_, i) => ({ ...DECODED_ENTRY, decoding_routine: i }));
    const r = parseFlossResult(floss({ decoded: many }))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.decodedString!;
    expect(block.citations.length).toBeLessThanOrEqual(64);
    expect(block.notCited).toBe(70 - block.citations.length);
    expect(block.occurrences).toBe(70);
  });
});

describe("parseFlossResult — oversized value is plain-truncated, never digest-spliced, never an IOC", () => {
  it("truncates a value over MAX_VALUE_LEN and never promotes it to an IOC even if URL-shaped", () => {
    const hugeUrl = "https://huge.example.com/" + "a".repeat(3000);
    const r = parseFlossResult(floss({ decoded: [{ ...DECODED_ENTRY, string: hugeUrl }] }))!;
    const block = r.events[0].canonical!.decodedString!;
    expect(block.valueTruncated).toBe(true);
    expect(block.value.length).toBeLessThanOrEqual(2000);
    expect(hugeUrl.startsWith(block.value)).toBe(true);
    expect(block.value.includes("#")).toBe(false);
    expect(r.iocs.some((i) => i.type === "url")).toBe(false);
  });
});

describe("parseFlossResult — reuse existing IOC matching (extractIocsFromText, the spec's own ask)", () => {
  it("extracts a URL from within a decoded string as a case IOC, authoritatively linked", () => {
    const r = parseFlossResult(
      floss({ decoded: [{ ...DECODED_ENTRY, string: "connect to http://c2.example.com/beacon now" }] }),
    )!;
    const urlIoc = r.iocs.find((i) => i.type === "url");
    expect(urlIoc?.value).toContain("c2.example.com");
    expect(urlIoc?.sourceAggKeys).toEqual([r.events[0].aggKey]);
  });

  it("a decoy/benign string with no IOC-shaped content still gets its event, no IOC added", () => {
    const r = parseFlossResult(floss({ decoded: [{ ...DECODED_ENTRY, string: "just a decoy string" }] }))!;
    expect(r.events).toHaveLength(1);
    expect(r.iocs.filter((i) => i.type !== "hash")).toHaveLength(0);
  });
});

describe("parseFlossResult — static_strings excluded by design, not a failure", () => {
  it("returns a real (non-null) result for a static-only upload, zero events, staticStringsSeen disclosed", () => {
    const r = parseFlossResult(
      floss({
        static_: [
          { string: "CODE", offset: 1, encoding: "ASCII" },
          { string: ".reloc", offset: 2, encoding: "ASCII" },
        ],
      }),
    );
    expect(r).not.toBeNull();
    expect(r!.events).toHaveLength(0);
    expect(r!.staticStringsSeen).toBe(2);
    expect(r!.staticStringsIocScanned).toBe(2);
    expect(r!.staticStringsIocFound).toBe(0);
  });

  it("extracts a URL from a static string as a case IOC, without creating any event for it (#1120)", () => {
    const r = parseFlossResult(
      floss({ static_: [{ string: "http://c2.example.com/beacon", offset: 1, encoding: "ASCII" }] }),
    )!;
    expect(r.events).toHaveLength(0);
    const urlIoc = r.iocs.find((i) => i.type === "url");
    expect(urlIoc?.value).toContain("c2.example.com");
    expect(r.staticStringsIocFound).toBeGreaterThan(0); // extractIocsFromText also yields a domain IOC alongside the url
  });

  it("still registers the sample's own hash as an IOC on a static-only report (#1120 — closes the gap where hash IOCs were silently dropped when zero events exist)", () => {
    const r = parseFlossResult(floss({ static_: [{ string: "CODE", offset: 1, encoding: "ASCII" }] }))!;
    const hashIocs = r.iocs.filter((i) => i.type === "hash").map((i) => i.value);
    expect(hashIocs).toContain(METADATA.sha256.toLowerCase());
  });

  it("skips a malformed static_strings entry (non-object, missing string) without counting it as malformedEntries", () => {
    const r = parseFlossResult(
      floss({ static_: ["not an object", { offset: 1, encoding: "ASCII" }, { string: "CODE", offset: 2 }] }),
    )!;
    expect(r.malformedEntries).toBe(0);
    expect(r.staticStringsIocScanned).toBe(3);
  });

  it("clips an oversized static string and skips IOC extraction on it (exact parity with the event path's own truncation rule)", () => {
    const hugeUrl = "http://huge.example.com/" + "a".repeat(3000);
    const r = parseFlossResult(floss({ static_: [{ string: hugeUrl, offset: 1, encoding: "ASCII" }] }))!;
    expect(r.iocs.some((i) => i.type === "url")).toBe(false);
    expect(r.staticStringsIocFound).toBe(0);
  });

  it("never crashes on a non-object entry in static_strings", () => {
    expect(() => parseFlossResult(floss({ static_: ["not an object", 42, null] }))).not.toThrow();
  });
});

describe("parseFlossResult — language_strings (#1120: confirmed language-runtime string table)", () => {
  it("maps a confirmed language string to a 'language' kind event with its own citation shape", () => {
    const r = parseFlossResult(
      floss({ metadata: { language: "go", language_version: "1.21" }, language: [LANGUAGE_ENTRY] }),
    )!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.decodedString!;
    expect(block.kind).toBe("language");
    expect(block.mappingVersion).toBe("floss-language-v1");
    if (block.kind === "language") {
      expect(block.citations[0]).toEqual({
        offset: 4096,
        encoding: "ASCII",
        language: "go",
        languageVersion: "1.21",
        missed: false,
      });
    }
    expect(r.events[0].description).not.toContain("candidate, not independently confirmed");
    expect(r.events[0].description).toContain("not proof of network contact or capability use");
  });

  it("defaults language/languageVersion to 'unknown' when metadata carries empty strings", () => {
    const r = parseFlossResult(floss({ language: [LANGUAGE_ENTRY] }))!;
    const block = r.events[0].canonical!.decodedString!;
    if (block.kind === "language") {
      expect(block.citations[0].language).toBe("unknown");
      expect(block.citations[0].languageVersion).toBe("unknown");
    }
  });

  it("defaults a missing encoding to 'unknown', never malformed, for a language string", () => {
    const r = parseFlossResult(floss({ language: [{ string: "x", offset: 1 }] }))!;
    expect(r.malformedEntries).toBe(0);
    const block = r.events[0].canonical!.decodedString!;
    if (block.kind === "language") expect(block.citations[0].encoding).toBe("unknown");
  });

  it("counts a language string entry missing 'string' or 'offset' as malformed", () => {
    const r = parseFlossResult(floss({ language: [{ encoding: "ASCII" }, { string: "x" }] }))!;
    expect(r.malformedEntries).toBe(2);
    expect(r.events).toHaveLength(0);
  });

  it("allows a negative offset (FLOSS's own field may be signed)", () => {
    const r = parseFlossResult(floss({ language: [{ ...LANGUAGE_ENTRY, offset: -4 }] }))!;
    expect(r.malformedEntries).toBe(0);
    expect(r.events).toHaveLength(1);
  });
});

describe("parseFlossResult — language_strings_missed (#1120: unconfirmed candidate)", () => {
  it("maps a missed-only value with missed:true and 'candidate, not independently confirmed' in the description", () => {
    const r = parseFlossResult(floss({ languageMissed: [LANGUAGE_ENTRY] }))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.decodedString!;
    if (block.kind === "language") expect(block.citations[0].missed).toBe(true);
    expect(r.events[0].description).toContain("candidate, not independently confirmed");
  });

  it("a value present in BOTH arrays reads as confirmed (any-confirmed wins), keeps both citations distinct, and sums occurrences across both", () => {
    const r = parseFlossResult(floss({ language: [LANGUAGE_ENTRY], languageMissed: [LANGUAGE_ENTRY] }))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.decodedString!;
    expect(r.events[0].description).not.toContain("candidate, not independently confirmed");
    if (block.kind === "language") {
      expect(block.occurrences).toBe(2);
      expect(block.citations).toHaveLength(2);
      expect(block.citations.some((c) => c.missed)).toBe(true);
      expect(block.citations.some((c) => !c.missed)).toBe(true);
    }
  });

  it("confirmed values keep their dedup slot over the MAX_DISTINCT_VALUES cap even when missed rows of a DIFFERENT value are scanned first in the array order (confirmed array is scanned first overall)", () => {
    const confirmed = { string: "confirmed-value", offset: 1, encoding: "ASCII" };
    const missedOnly = Array.from({ length: 2000 }, (_, i) => ({
      string: `missed-${i}`,
      offset: i,
      encoding: "ASCII",
    }));
    const r = parseFlossResult(floss({ language: [confirmed], languageMissed: missedOnly }))!;
    const kinds = r.events.map((e) => e.canonical!.decodedString!);
    const confirmedEvent = kinds.find((k) => k.value === "confirmed-value");
    expect(confirmedEvent).toBeDefined();
    expect(r.notCitedValues).toBeGreaterThan(0); // some missed-only values overflowed the cap instead
  });

  it("keeps the ONE confirmed citation of a value over the RECOVERY_CITATIONS_MAX cap when the SAME value has more missed citations than the cap (#1305 — confirmed-first is mapGroup's own guarantee, not the caller's scan order)", () => {
    const confirmed = { ...LANGUAGE_ENTRY, offset: 999999 };
    const missed = Array.from({ length: 64 + 6 }, (_, i) => ({ ...LANGUAGE_ENTRY, offset: i }));
    const r = parseFlossResult(floss({ language: [confirmed], languageMissed: missed }))!;
    expect(r.events).toHaveLength(1);
    const block = r.events[0].canonical!.decodedString!;
    expect(block.kind).toBe("language");
    if (block.kind === "language") {
      expect(block.citations).toHaveLength(64);
      expect(block.notCited).toBe(7);
      expect(block.occurrences).toBe(71);
      expect(block.citations.some((c) => !c.missed)).toBe(true);
      expect(block.citations[0].missed).toBe(false);
    }
    expect(r.events[0].description).not.toContain("candidate, not independently confirmed");
  });
});

describe("isFlossResult — language-only recognition (#1120)", () => {
  it("recognizes a language-only upload (no decoded/stack/tight/static)", () => {
    expect(isFlossResult(JSON.parse(floss({ language: [LANGUAGE_ENTRY] })))).toBe(true);
  });
});

describe("parseFlossResult — malformed entries are skipped and truthfully accounted, never crash", () => {
  it("skips a decoded_strings entry missing a required field, disclosed via malformedEntries/dropped, not silently absorbed into total (Codex code review finding)", () => {
    const malformed = { string: "no address field", encoding: "ASCII", decoded_at: 1, decoding_routine: 2 };
    const r = parseFlossResult(floss({ decoded: [malformed, DECODED_ENTRY] }))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedEntries).toBe(1);
    expect(r.dropped).toBe(1);
    expect(r.total).toBe(2); // both examined entries counted, one malformed and one kept
  });

  it("never crashes on a non-object entry in a strings array", () => {
    expect(() => parseFlossResult(floss({ decoded: ["not an object", DECODED_ENTRY] }))).not.toThrow();
  });

  it("never crashes and counts as malformed when a numeric field is fractional, negative, or unsafe (Codex code review finding — a value that reached the schema would have thrown)", () => {
    const fractional = { ...DECODED_ENTRY, string: "s1", address: 1.5 };
    const negative = { ...DECODED_ENTRY, string: "s2", decoded_at: -1 };
    const unsafe = { ...DECODED_ENTRY, string: "s3", decoding_routine: Number.MAX_SAFE_INTEGER + 1 };
    expect(() => parseFlossResult(floss({ decoded: [fractional, negative, unsafe] }))).not.toThrow();
    const r = parseFlossResult(floss({ decoded: [fractional, negative, unsafe] }))!;
    expect(r.events).toHaveLength(0);
    expect(r.malformedEntries).toBe(3);
  });

  it("allows a genuinely negative frame_offset for stack/tight strings (FLOSS's own field can be signed)", () => {
    const r = parseFlossResult(floss({ stack: [STACK_ENTRY] }))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedEntries).toBe(0);
  });
});

describe("parseFlossResult — false detection / malformed JSON", () => {
  it("returns null for text that isn't valid JSON", () => {
    expect(parseFlossResult("not json at all")).toBeNull();
  });

  it("returns null for valid JSON that isn't a FLOSS document", () => {
    expect(parseFlossResult(JSON.stringify({ hello: "world" }))).toBeNull();
  });
});

describe("parseFlossResult — MAX_ENTRIES_SCANNED scan order (#1120, Ollama design review finding 10)", () => {
  it("a huge static_strings array never starves decoded/stack/tight/language (static is scanned strictly last)", () => {
    const huge = Array.from({ length: 150_000 }, (_, i) => ({
      string: `static-${i}`,
      offset: i,
      encoding: "ASCII",
    }));
    const r = parseFlossResult(floss({ decoded: [DECODED_ENTRY], static_: huge }))!;
    expect(r.events).toHaveLength(1);
    expect(r.malformedEntries).toBe(0);
    expect(r.entriesTruncated).toBe(true); // static itself gets cut off
    expect(r.staticStringsIocScanned).toBeLessThan(r.staticStringsSeen);
  });

  it("huge event-kind volume correctly starves static_strings to zero", () => {
    const hugeDecoded = Array.from({ length: 100_000 }, (_, i) => ({
      ...DECODED_ENTRY,
      decoding_routine: i,
    }));
    const r = parseFlossResult(
      floss({ decoded: hugeDecoded, static_: [{ string: "CODE", offset: 1, encoding: "ASCII" }] }),
    )!;
    expect(r.entriesTruncated).toBe(true);
    expect(r.staticStringsIocScanned).toBe(0);
    expect(r.staticStringsSeen).toBe(1);
  });

  it("never drops an IOC found before the budget cutoff mid-array (Ollama code review finding — an early return used to skip the merge)", () => {
    const almostFullDecoded = Array.from({ length: 99_995 }, (_, i) => ({
      ...DECODED_ENTRY,
      decoding_routine: i,
    }));
    // 99_995 (decoded) + 5 (static) = 100_000: the first 5 static entries are visited and
    // processed normally, the 6th trips the budget guard and must never lose the first 5's IOCs.
    const staticEntries = [
      { string: "http://c2.example.com/beacon", offset: 1, encoding: "ASCII" },
      { string: "http://second.example.com/beacon", offset: 2, encoding: "ASCII" },
      { string: "http://third.example.com/beacon", offset: 3, encoding: "ASCII" },
      { string: "http://fourth.example.com/beacon", offset: 4, encoding: "ASCII" },
      { string: "http://fifth.example.com/beacon", offset: 5, encoding: "ASCII" },
      { string: "http://never-visited.example.com/beacon", offset: 6, encoding: "ASCII" },
    ];
    const r = parseFlossResult(floss({ decoded: almostFullDecoded, static_: staticEntries }))!;
    expect(r.entriesTruncated).toBe(true);
    expect(r.staticStringsIocScanned).toBe(5); // 99_995 + 5 = 100_000, the 6th entry never visited
    const urlIocs = r.iocs.filter((i) => i.type === "url").map((i) => i.value);
    expect(urlIocs.some((v) => v.includes("c2.example.com"))).toBe(true);
    expect(urlIocs.some((v) => v.includes("second.example.com"))).toBe(true);
  });
});
