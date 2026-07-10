import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  hashCasePassword,
  verifyCasePassword,
  sanitizeCaseMeta,
  signUnlockToken,
  verifyUnlockToken,
  isRememberedUnlockToken,
  unlockCookieName,
  parseCookieHeader,
  MIN_CASE_PASSWORD_LENGTH,
} from "../../src/analysis/casePassword.js";
import type { CaseMeta } from "../../src/types.js";

describe("hashCasePassword / verifyCasePassword", () => {
  it("verifies the correct password", () => {
    const hash = hashCasePassword("correct horse battery staple");
    expect(verifyCasePassword("correct horse battery staple", hash)).toBe(true);
  });
  it("rejects the wrong password", () => {
    const hash = hashCasePassword("correct horse battery staple");
    expect(verifyCasePassword("wrong password", hash)).toBe(false);
  });
  it("produces a different salt and hash each call, even for the same password", () => {
    const a = hashCasePassword("same-password");
    const b = hashCasePassword("same-password");
    expect(a.salt).not.toBe(b.salt);
    expect(a.hash).not.toBe(b.hash);
  });
});

describe("sanitizeCaseMeta", () => {
  const base: CaseMeta = { caseId: "c1", name: "n", createdAt: "t", investigator: "i", aiProvider: null };

  it("replaces password with hasPassword:true and never leaks the hash", () => {
    const meta: CaseMeta = { ...base, password: hashCasePassword("secret") };
    const out = sanitizeCaseMeta(meta);
    expect(out.hasPassword).toBe(true);
    expect((out as Record<string, unknown>).password).toBeUndefined();
    expect(JSON.stringify(out)).not.toContain("hash");
  });
  it("hasPassword is false when no password is set", () => {
    expect(sanitizeCaseMeta(base).hasPassword).toBe(false);
  });
  it("preserves every other field", () => {
    const out = sanitizeCaseMeta({ ...base, status: "closed" });
    expect(out.caseId).toBe("c1");
    expect(out.name).toBe("n");
    expect(out.investigator).toBe("i");
    expect(out.status).toBe("closed");
  });
});

describe("signUnlockToken / verifyUnlockToken", () => {
  const secret = randomBytes(32);

  it("round-trips a freshly signed token", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, false);
    expect(verifyUnlockToken(token, "c1", "salt-a", secret)).toBe(true);
  });
  it("rejects a token checked against a different caseId", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, false);
    expect(verifyUnlockToken(token, "c2", "salt-a", secret)).toBe(false);
  });
  it("rejects a token whose salt no longer matches (password was changed)", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, false);
    expect(verifyUnlockToken(token, "c1", "salt-b", secret)).toBe(false);
  });
  it("rejects a tampered token", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, false);
    const flipped = token.slice(0, -1) + (token.endsWith("A") ? "B" : "A");
    expect(verifyUnlockToken(flipped, "c1", "salt-a", secret)).toBe(false);
  });
  it("rejects an already-expired token", () => {
    const token = signUnlockToken("c1", "salt-a", secret, -1, false);
    expect(verifyUnlockToken(token, "c1", "salt-a", secret)).toBe(false);
  });
  it("rejects a token signed with a different secret", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, false);
    expect(verifyUnlockToken(token, "c1", "salt-a", randomBytes(32))).toBe(false);
  });
  it("rejects garbage input without throwing", () => {
    expect(verifyUnlockToken("not-a-token", "c1", "salt-a", secret)).toBe(false);
    expect(verifyUnlockToken("", "c1", "salt-a", secret)).toBe(false);
  });
});

describe("isRememberedUnlockToken", () => {
  const secret = randomBytes(32);

  it("is true for a token signed with remember=true", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, true);
    expect(isRememberedUnlockToken(token, "c1", "salt-a", secret)).toBe(true);
  });
  it("is false for a token signed with remember=false", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, false);
    expect(isRememberedUnlockToken(token, "c1", "salt-a", secret)).toBe(false);
  });
  it("is false for an otherwise-invalid token (wrong caseId, tampered, expired, garbage)", () => {
    const token = signUnlockToken("c1", "salt-a", secret, 60_000, true);
    expect(isRememberedUnlockToken(token, "c2", "salt-a", secret)).toBe(false);
    const expired = signUnlockToken("c1", "salt-a", secret, -1, true);
    expect(isRememberedUnlockToken(expired, "c1", "salt-a", secret)).toBe(false);
    expect(isRememberedUnlockToken("not-a-token", "c1", "salt-a", secret)).toBe(false);
  });
});

describe("parseCookieHeader", () => {
  it("parses multiple cookies", () => {
    expect(parseCookieHeader("a=1; b=2")).toEqual({ a: "1", b: "2" });
  });
  it("returns {} for an undefined header", () => {
    expect(parseCookieHeader(undefined)).toEqual({});
  });
  it("URL-decodes values", () => {
    expect(parseCookieHeader("tok=" + encodeURIComponent("a.b/c"))).toEqual({ tok: "a.b/c" });
  });
});

describe("unlockCookieName", () => {
  it("is stable and namespaced per case", () => {
    expect(unlockCookieName("c1")).toBe("dfir_unlock_c1");
    expect(unlockCookieName("c1")).not.toBe(unlockCookieName("c2"));
  });
});

describe("MIN_CASE_PASSWORD_LENGTH", () => {
  it("is at least 6", () => {
    expect(MIN_CASE_PASSWORD_LENGTH).toBeGreaterThanOrEqual(6);
  });
});
