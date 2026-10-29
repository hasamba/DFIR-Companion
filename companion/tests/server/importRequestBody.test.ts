import { describe, it, expect } from "vitest";
import {
  importBodyError,
  importBodyText,
  MAX_SOURCE_URL_LENGTH,
  withSourceUrl,
} from "../../src/routes/importRequestBody.js";

// #2258 — the extension sends the page URL an artifact was pushed from. It is provenance for the
// import audit log only (metadata/imports.jsonl), so it is validated strictly and never echoed into
// anything the AI reads.
describe("importBodyText", () => {
  it("prefers text, then json, then csv", () => {
    expect(importBodyText({ text: "t", json: "j", csv: "c" })).toBe("t");
    expect(importBodyText({ json: "j", csv: "c" })).toBe("j");
    expect(importBodyText({ csv: "c" })).toBe("c");
  });

  it("returns an empty string for a missing or non-string body", () => {
    expect(importBodyText(undefined)).toBe("");
    expect(importBodyText({ text: 5 })).toBe("");
  });
});

describe("importBodyError", () => {
  it("requires non-blank text", () => {
    expect(importBodyError("   ", undefined)).toBe("text is required");
  });

  it("accepts a body with no sourceUrl", () => {
    expect(importBodyError("x", undefined)).toBeUndefined();
  });

  it("accepts an http or https sourceUrl", () => {
    expect(importBodyError("x", "https://console.example/app#/hunts")).toBeUndefined();
    expect(importBodyError("x", "http://127.0.0.1:8889/app")).toBeUndefined();
  });

  it.each([
    ["a non-string", 42],
    ["a javascript: URL", "javascript:alert(1)"],
    ["a file: URL", "file:///etc/passwd"],
    ["an unparseable string", "not a url"],
    ["an over-long URL", `https://e.example/${"a".repeat(MAX_SOURCE_URL_LENGTH)}`],
  ])("rejects %s", (_label, value) => {
    expect(importBodyError("x", value)).toMatch(/sourceUrl/);
  });
});

describe("withSourceUrl", () => {
  const meta = { caseId: "c1", sequenceNumber: 1 };

  it("adds a valid sourceUrl without mutating the input", () => {
    const out = withSourceUrl("https://console.example/x", meta);
    expect(out).toEqual({ ...meta, sourceUrl: "https://console.example/x" });
    expect(meta).not.toHaveProperty("sourceUrl");
  });

  it("leaves the metadata unchanged when sourceUrl is absent or empty", () => {
    expect(withSourceUrl(undefined, meta)).toEqual(meta);
    expect(withSourceUrl("", meta)).toEqual(meta);
  });
});
