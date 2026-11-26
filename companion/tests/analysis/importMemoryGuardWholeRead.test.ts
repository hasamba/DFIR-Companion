// #2823: a file that is still read whole (a SIEM single-document JSON, a UTF-16 export) costs memory
// per BYTE, not per kept row — a 100 MB SIEM file kept at 2,000 rows peaked ~0.9 GB RSS / 660 MB heap
// above idle. Such a caller says so with `wholeRead`, and the incoming part of the estimate becomes
// the larger of the event figure and the file figure (max, never a sum). Streamed callers and small
// files are unchanged.
import { describe, it, expect } from "vitest";
import {
  assessImportMemory,
  createImportMemoryGuard,
  ImportMemoryRefusedError,
  IMPORT_RSS_BYTES_PER_EVENT,
  IMPORT_HEAP_BYTES_PER_EVENT,
  IMPORT_RSS_BYTES_PER_INPUT_BYTE,
  IMPORT_HEAP_BYTES_PER_INPUT_BYTE,
} from "../../src/analysis/importMemoryGuard.js";

const GB = 1024 ** 3;
const MB = 1024 ** 2;
const roomy = { availableBytes: 16 * GB, rssBytes: 0.5 * GB, heapLimitBytes: 8 * GB, reservedBytes: 0 };

describe("assessImportMemory with a whole-read file", () => {
  it("covers the measured 100 MB peak (0.9 GB RSS, 660 MB heap) with the file term", () => {
    const verdict = assessImportMemory({
      caseEvents: 0,
      incomingEvents: 2_000,
      wholeReadBytes: 100 * MB,
      ...roomy,
    });
    if (!verdict.ok) throw new Error("expected admission");
    expect(verdict.needBytes).toBeGreaterThanOrEqual(0.9 * GB);
    expect(verdict.heapNeedBytes).toBeGreaterThanOrEqual(660 * MB);
  });

  it("takes the larger incoming term, never the sum, and still adds the case", () => {
    const caseEvents = 50_000;
    const bytes = 100 * MB;
    const verdict = assessImportMemory({
      caseEvents,
      incomingEvents: 2_000,
      wholeReadBytes: bytes,
      ...roomy,
    });
    if (!verdict.ok) throw new Error("expected admission");
    expect(verdict.needBytes).toBe(
      caseEvents * IMPORT_RSS_BYTES_PER_EVENT + bytes * IMPORT_RSS_BYTES_PER_INPUT_BYTE,
    );
    expect(verdict.heapNeedBytes).toBe(
      caseEvents * IMPORT_HEAP_BYTES_PER_EVENT + bytes * IMPORT_HEAP_BYTES_PER_INPUT_BYTE,
    );
    // An uncapped import whose event term is larger is charged its events alone, not events + file.
    const many = assessImportMemory({
      caseEvents: 0,
      incomingEvents: 20_000,
      wholeReadBytes: 10 * MB,
      ...roomy,
    });
    if (!many.ok) throw new Error("expected admission");
    expect(many.needBytes).toBe(20_000 * IMPORT_RSS_BYTES_PER_EVENT);
  });

  it("leaves a small whole-read file's estimate exactly as before", () => {
    const base = { caseEvents: 10_000, incomingEvents: 2_000, ...roomy };
    const before = assessImportMemory(base);
    const after = assessImportMemory({ ...base, wholeReadBytes: 2 * MB });
    expect(after).toEqual(before);
  });

  it("names the file size when the file term decides the refusal", () => {
    const verdict = assessImportMemory({
      caseEvents: 1_000,
      incomingEvents: 2_000,
      wholeReadBytes: 180 * MB,
      ...roomy,
      availableBytes: 1 * GB,
      rssBytes: 0,
    });
    expect(verdict.ok).toBe(false);
    if (verdict.ok) return;
    expect(verdict.message).toMatch(/180 MB file/);
    expect(verdict.message).toMatch(/file whole/);
    expect(verdict.message).toMatch(/DFIR_IMPORT_MEMORY_GUARD=off/);
  });

  it("keeps the events wording when the event term decides", () => {
    const verdict = assessImportMemory({
      caseEvents: 140_000,
      incomingEvents: 2_000,
      wholeReadBytes: 1 * MB,
      ...roomy,
      availableBytes: 4 * GB,
    });
    if (verdict.ok) throw new Error("expected refusal");
    expect(verdict.message).not.toMatch(/file whole/);
    expect(verdict.message).toMatch(/140,000 events/);
  });
});

describe("createImportMemoryGuard with a whole-read hint", () => {
  const guardWith = (availableBytes: number, events = 0) =>
    createImportMemoryGuard({
      countEvents: async () => events,
      probe: () => ({ availableBytes, rssBytes: 0, heapLimitBytes: 8 * GB }),
      maxEvents: () => 2_000,
    });

  it("charges only a caller that says it reads whole: the same size streamed is admitted", async () => {
    const guard = guardWith(0.6 * GB);
    const release = await guard.admit("c1", { incomingBytes: 100 * MB });
    release();
    await expect(guard.admit("c1", { incomingBytes: 100 * MB, wholeRead: true })).rejects.toBeInstanceOf(
      ImportMemoryRefusedError,
    );
  });

  it("reserves the file figure, so a second import sees it held", async () => {
    const guard = guardWith(16 * GB);
    const release = await guard.admit("c1", { incomingBytes: 100 * MB, wholeRead: true });
    expect(guard.reservedBytes()).toBe(100 * MB * IMPORT_RSS_BYTES_PER_INPUT_BYTE);
    release();
    expect(guard.reservedBytes()).toBe(0);
  });

  it("keeps the file term through a section re-check as the case grows", async () => {
    let events = 0;
    const guard = createImportMemoryGuard({
      countEvents: async () => events,
      probe: () => ({ availableBytes: 16 * GB, rssBytes: 0, heapLimitBytes: 8 * GB }),
      maxEvents: () => 2_000,
    });
    const release = await guard.admit("c1", { incomingBytes: 100 * MB, wholeRead: true }, { section: true });
    events = 10_000;
    const check = await guard.openSectionCheck("c1");
    check?.(5_000);
    expect(guard.reservedBytes()).toBe(
      10_000 * IMPORT_RSS_BYTES_PER_EVENT + 100 * MB * IMPORT_RSS_BYTES_PER_INPUT_BYTE,
    );
    release();
    expect(guard.reservedBytes()).toBe(0);
  });
});
