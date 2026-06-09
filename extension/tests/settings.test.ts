import { describe, it, expect } from "vitest";
import { DEFAULT_SETTINGS, normalizeCompanionUrl } from "../src/types.js";

describe("normalizeCompanionUrl", () => {
  it("returns a clean URL unchanged", () => {
    expect(normalizeCompanionUrl("http://127.0.0.1:4773")).toBe("http://127.0.0.1:4773");
  });

  it("strips a single trailing slash", () => {
    expect(normalizeCompanionUrl("http://127.0.0.1:4773/")).toBe("http://127.0.0.1:4773");
  });

  it("strips multiple trailing slashes", () => {
    expect(normalizeCompanionUrl("http://127.0.0.1:4773///")).toBe("http://127.0.0.1:4773");
  });

  it("trims surrounding whitespace", () => {
    expect(normalizeCompanionUrl("  http://127.0.0.1:4773  ")).toBe("http://127.0.0.1:4773");
  });

  it("falls back to the default when the value is empty", () => {
    expect(normalizeCompanionUrl("")).toBe(DEFAULT_SETTINGS.companionUrl);
  });

  it("falls back to the default when the value is only whitespace", () => {
    expect(normalizeCompanionUrl("   ")).toBe(DEFAULT_SETTINGS.companionUrl);
  });

  it("supports a custom host and port", () => {
    expect(normalizeCompanionUrl("http://192.168.1.100:9000")).toBe("http://192.168.1.100:9000");
  });

  it("supports a named host with a custom port", () => {
    expect(normalizeCompanionUrl("http://companion.local:4773/")).toBe("http://companion.local:4773");
  });
});
