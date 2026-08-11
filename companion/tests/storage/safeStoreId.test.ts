import { describe, it, expect } from "vitest";
import { join, resolve, sep } from "node:path";
import { assertSafeStoreId, storeFilePath, UnsafeStoreIdError } from "../../src/storage/safeStoreId.js";

const ROOT = resolve("/tmp/dfir-store-root");

describe("assertSafeStoreId", () => {
  it("accepts the id shapes the stores actually use", () => {
    // Server-generated UUIDs and the shipped built-in ids.
    expect(assertSafeStoreId("6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8")).toBe(
      "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
    );
    expect(assertSafeStoreId("best-practice")).toBe("best-practice");
    expect(assertSafeStoreId("super-timeline-triage")).toBe("super-timeline-triage");
    expect(assertSafeStoreId("general-malware")).toBe("general-malware");
    expect(assertSafeStoreId("report_v2.final")).toBe("report_v2.final");
  });

  it("trims surrounding whitespace before validating", () => {
    expect(assertSafeStoreId("  linux-triage  ")).toBe("linux-triage");
  });

  it("rejects traversal components", () => {
    expect(() => assertSafeStoreId("..")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("../evil")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("../../etc/passwd")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("..\\..\\evil")).toThrow(UnsafeStoreIdError);
  });

  it("rejects path separators of either flavour", () => {
    expect(() => assertSafeStoreId("a/b")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("a\\b")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("/absolute")).toThrow(UnsafeStoreIdError);
  });

  it("rejects Windows drive and UNC prefixes", () => {
    expect(() => assertSafeStoreId("C:evil")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("C:\\Windows\\System32\\config")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("\\\\server\\share\\x")).toThrow(UnsafeStoreIdError);
  });

  it("rejects a still-encoded traversal attempt rather than decoding it", () => {
    // Express already decodes :params, so a surviving %2e is not a legitimate id either way.
    expect(() => assertSafeStoreId("%2e%2e%2fevil")).toThrow(UnsafeStoreIdError);
  });

  it("rejects ids that are empty, blank, or hidden-file style", () => {
    expect(() => assertSafeStoreId("")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("   ")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId(".")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId(".hidden")).toThrow(UnsafeStoreIdError);
  });

  it("rejects NUL bytes and other control characters", () => {
    expect(() => assertSafeStoreId("evil\u0000.json")).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId("evil\nid")).toThrow(UnsafeStoreIdError);
  });

  it("rejects an absurdly long id", () => {
    expect(() => assertSafeStoreId("a".repeat(200))).toThrow(UnsafeStoreIdError);
  });

  it("rejects a non-string id", () => {
    expect(() => assertSafeStoreId(undefined as unknown as string)).toThrow(UnsafeStoreIdError);
    expect(() => assertSafeStoreId({ toString: () => "../evil" } as unknown as string)).toThrow(
      UnsafeStoreIdError,
    );
  });
});

describe("storeFilePath", () => {
  it("resolves a valid id to <root>/<id>.json", () => {
    expect(storeFilePath(ROOT, "best-practice")).toBe(join(ROOT, "best-practice.json"));
  });

  it("never returns a path outside the root", () => {
    expect(() => storeFilePath(ROOT, "../evil")).toThrow(UnsafeStoreIdError);
    expect(() => storeFilePath(ROOT, "..")).toThrow(UnsafeStoreIdError);
    // Belt and braces: whatever the id, the result stays beneath the root.
    for (const id of ["a", "a.b", "a-b_c", "0"]) {
      expect(storeFilePath(ROOT, id).startsWith(ROOT + sep)).toBe(true);
    }
  });
});
