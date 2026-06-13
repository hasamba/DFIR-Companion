import { describe, it, expect } from "vitest";
import { resolvePushAuth, timingSafeEqual } from "../../src/analysis/pushAuth.js";

describe("pushAuth", () => {
  describe("timingSafeEqual", () => {
    it("is true for equal strings, false otherwise", () => {
      expect(timingSafeEqual("abc123", "abc123")).toBe(true);
      expect(timingSafeEqual("abc123", "abc124")).toBe(false);
      expect(timingSafeEqual("abc", "abcd")).toBe(false);   // length mismatch
      expect(timingSafeEqual("", "")).toBe(true);
    });
  });

  describe("resolvePushAuth", () => {
    it("denies with 403 when no token is configured anywhere", () => {
      const r = resolvePushAuth({ presented: "anything" });
      expect(r.ok).toBe(false);
      expect(r.status).toBe(403);
      expect(r.error).toMatch(/disabled/i);
    });

    it("401s when a token is configured but none is presented", () => {
      const r = resolvePushAuth({ globalToken: "secret", presented: "" });
      expect(r.ok).toBe(false);
      expect(r.status).toBe(401);
      expect(r.error).toMatch(/missing/i);
    });

    it("accepts a matching global token", () => {
      expect(resolvePushAuth({ globalToken: "secret", presented: "secret" }).ok).toBe(true);
    });

    it("accepts a matching per-case token", () => {
      expect(resolvePushAuth({ caseToken: "casetok", presented: "casetok" }).ok).toBe(true);
    });

    it("accepts either token when both are configured", () => {
      expect(resolvePushAuth({ globalToken: "g", caseToken: "c", presented: "g" }).ok).toBe(true);
      expect(resolvePushAuth({ globalToken: "g", caseToken: "c", presented: "c" }).ok).toBe(true);
    });

    it("401s a wrong key when a token is configured", () => {
      const r = resolvePushAuth({ globalToken: "secret", presented: "nope" });
      expect(r.ok).toBe(false);
      expect(r.status).toBe(401);
      expect(r.error).toMatch(/invalid/i);
    });

    it("trims tokens (a trailing newline in a token file still matches)", () => {
      expect(resolvePushAuth({ caseToken: "tok\n", presented: " tok " }).ok).toBe(true);
    });
  });
});
