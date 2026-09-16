import { describe, it, expect } from "vitest";
import { yaraMappingContext } from "../../src/analysis/memoryYaraMappingContext.js";

describe("yaraMappingContext — mappingClass classification", () => {
  it("classifies each of MemProcFS's own 4 real MemoryType values", () => {
    expect(yaraMappingContext("Virtual Memory (VAD)", "").mappingClass).toBe("process-user-mode");
    expect(yaraMappingContext("Virtual Memory (PTE)", "").mappingClass).toBe("process-kernel-mode");
    expect(yaraMappingContext("Object Memory", "").mappingClass).toBe("object");
    expect(yaraMappingContext("Physical Memory", "").mappingClass).toBe("no-process-context");
  });

  it("never crashes and never treats an unrecognized value as the strongest case", () => {
    const r = yaraMappingContext("Something MemProcFS has not emitted yet", "tag");
    expect(r.mappingClass).toBe("unrecognized");
    expect(r.note).not.toMatch(/private allocation|does not establish exclusive/i);
  });
});

describe("yaraMappingContext — tagBacking, three-plus-one states", () => {
  it("is 'absent' only for a truly empty tag", () => {
    expect(yaraMappingContext("Virtual Memory (VAD)", "").tagBacking).toBe("absent");
  });

  it("is 'file-backed-likely' for a path or narrow PE-extension tag", () => {
    expect(
      yaraMappingContext("Virtual Memory (VAD)", "\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll")
        .tagBacking,
    ).toBe("file-backed-likely");
    expect(yaraMappingContext("Virtual Memory (VAD)", "C:\\evil.exe").tagBacking).toBe("file-backed-likely");
  });

  it("is 'private-allocation-likely' for this codebase's own real observed heap/stack tag shape", () => {
    // Real fixture shape confirmed in this repo's own tests/analysis/memoryImport.test.ts.
    expect(yaraMappingContext("Virtual Memory (VAD)", "HEAP-00 [SegSegment]").tagBacking).toBe(
      "private-allocation-likely",
    );
    expect(yaraMappingContext("Virtual Memory (VAD)", "STACK-01").tagBacking).toBe(
      "private-allocation-likely",
    );
  });

  it("is 'unclassified' for a non-empty tag matching neither shape — text WAS recovered", () => {
    const r = yaraMappingContext("Virtual Memory (VAD)", "some-opaque-descriptor");
    expect(r.tagBacking).toBe("unclassified");
    expect(r.note).not.toMatch(/no region label was recovered/i);
  });

  it("never applies a tagBacking classification to object/no-process-context/unrecognized rows", () => {
    expect(yaraMappingContext("Object Memory", "ntdll.dll").tagBacking).toBe("absent");
    expect(yaraMappingContext("Physical Memory", "").tagBacking).toBe("absent");
  });
});

describe("yaraMappingContext — note never claims confirmed sharing or confirmed exclusivity", () => {
  const ALL_INPUTS: Array<[string, string]> = [
    ["Virtual Memory (VAD)", ""],
    ["Virtual Memory (VAD)", "HEAP-00 [SegSegment]"],
    ["Virtual Memory (VAD)", "C:\\evil.dll"],
    ["Virtual Memory (VAD)", "opaque"],
    ["Virtual Memory (PTE)", ""],
    ["Virtual Memory (PTE)", "some-pte-tag"],
    ["Object Memory", "tag"],
    ["Physical Memory", ""],
    ["unknown-future-value", ""],
  ];

  it("never says 'is shared' or 'is exclusive' as an unqualified fact", () => {
    for (const [memType, tag] of ALL_INPUTS) {
      const note = yaraMappingContext(memType, tag).note;
      expect(note).not.toMatch(/\bis shared\b/i);
      expect(note).not.toMatch(/\bis exclusive\b/i);
      expect(note).not.toMatch(/\bis exclusively owned\b/i);
    }
  });

  it("states 'does not establish exclusive' for a file-backed-likely region", () => {
    const note = yaraMappingContext("Virtual Memory (VAD)", "ntdll.dll").note;
    expect(note).toMatch(/does not establish exclusive/i);
  });

  it("states the kernel-mode disclaimer without asserting sharing as fact", () => {
    const note = yaraMappingContext("Virtual Memory (PTE)", "").note;
    expect(note).toMatch(/does not establish exclusive/i);
    expect(note).not.toMatch(/shared machine-wide/i);
  });
});

describe("yaraMappingContext — the pagefile-provenance limitation is honest, not a false claim", () => {
  it("states the export cannot identify pagefile provenance, never that a pagefile match 'would surface this way'", () => {
    const note = yaraMappingContext("Physical Memory", "").note;
    expect(note).toMatch(/cannot identify pagefile/i);
    expect(note).not.toMatch(/would also surface this way/i);
  });
});

describe("yaraMappingContext — object rows", () => {
  it("says 'typically a file object', not a vague 'kernel object'", () => {
    const note = yaraMappingContext("Object Memory", "\\some\\file.txt").note;
    expect(note).toMatch(/file object/i);
  });
});

describe("yaraMappingContext — bounded interpolation", () => {
  it("never lets an extremely long tag blow past a reasonable note length", () => {
    const longTag = "a".repeat(2000);
    const note = yaraMappingContext("Virtual Memory (VAD)", longTag).note;
    expect(note.length).toBeLessThan(500);
  });

  it("puts the qualifying clause before the interpolated tag text for a file-backed-likely region", () => {
    const note = yaraMappingContext("Virtual Memory (VAD)", "C:\\evil.dll").note;
    const qualIdx = note.toLowerCase().indexOf("does not establish exclusive");
    const tagIdx = note.indexOf("evil.dll");
    expect(qualIdx).toBeGreaterThanOrEqual(0);
    expect(tagIdx).toBeGreaterThan(qualIdx);
  });
});

// Codex code-review finding: the "Physical Memory" and "unrecognized" notes exceeded the old
// 260-char cap and were truncated mid-sentence, silently dropping the pagefile-provenance
// qualification the earlier tests only checked the START of.
describe("yaraMappingContext — no note is ever truncated mid-sentence (regression)", () => {
  it("the Physical Memory note ends on its own terminal punctuation, never mid-word", () => {
    const note = yaraMappingContext("Physical Memory", "").note;
    expect(note.endsWith(".")).toBe(true);
    expect(note).toContain(
      "cannot identify pagefile-only provenance, so a pagefile-backed string, if one exists, is not distinguishable from this.",
    );
  });

  it("the unrecognized-type note ends on its own terminal punctuation, never mid-word, even at a maximal memoryType length", () => {
    const note = yaraMappingContext("x".repeat(200), "").note;
    expect(note.endsWith(".")).toBe(true);
    expect(note).toContain("pagefile-backed string, if one exists, is not distinguishable from this.");
  });
});

// Codex code-review finding: the PTE branch discarded its own recovered MemoryTag entirely,
// dropping analyst-visible evidence (e.g. a driver/module name) that survived for every other class.
describe("yaraMappingContext — process-kernel-mode preserves its own recovered tag", () => {
  it("includes the tag text when one was recovered", () => {
    const note = yaraMappingContext("Virtual Memory (PTE)", "ntoskrnl.exe").note;
    expect(note).toContain("ntoskrnl.exe");
  });

  it("says nothing extra when no tag was recovered", () => {
    const note = yaraMappingContext("Virtual Memory (PTE)", "").note;
    expect(note).not.toContain("Recovered label");
  });
});
