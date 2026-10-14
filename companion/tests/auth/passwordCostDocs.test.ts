import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CASE_PASSWORD_SCRYPT_N, hashCasePassword } from "../../src/analysis/casePassword.js";
import { hashLocalPassword, LOCAL_PASSWORD_SCRYPT_N } from "../../src/auth/password.js";
import { UNLOCK_IP_MAX_FAILURES } from "../../src/http/rateLimiter.js";

// STORED-PASSWORD SCRYPT COST MUST BE DOCUMENTED WHERE THE .dfircase BAR IS (#2167).
//
// SECURITY.md calls N=2^14 "too low" for a .dfircase archive, while team-mode local accounts and
// case-lock passwords both hash at N=2^14 with no explanation. The difference is deliberate — those
// two are checked online, behind a rate limiter, and a higher N makes every admitted attempt a
// bigger CPU lever — but it has to be written down, and raising N must not leave the table stale.
const root = new URL("../../../", import.meta.url);
const security = readFileSync(new URL("SECURITY.md", root), "utf8");

function storedPasswordsSection(md: string): string {
  const start = md.indexOf("## Stored passwords");
  if (start === -1) return "";
  const next = md.indexOf("\n## ", start + 1);
  return md.slice(start, next === -1 ? undefined : next);
}

function formatN(n: number): string {
  return `2^${Math.log2(n)} (${n.toLocaleString("en-US")})`;
}

describe("SECURITY.md documents the stored-password scrypt cost (#2167)", () => {
  const section = storedPasswordsSection(security);

  it("has a Stored passwords section", () => {
    expect(section).not.toBe("");
  });

  it("states the team-mode local account N as the code uses it", () => {
    expect(section).toMatch(/team-mode local account/i);
    expect(section).toContain(formatN(LOCAL_PASSWORD_SCRYPT_N));
  });

  it("states the case-lock password N as the code uses it", () => {
    expect(section).toMatch(/case-lock password/i);
    expect(section).toContain(formatN(CASE_PASSWORD_SCRYPT_N));
  });

  it("gives the online-vs-offline rationale and tells admins to protect auth.sqlite", () => {
    expect(section).toMatch(/online/i);
    expect(section).toMatch(/rate-limited/i);
    expect(section).toMatch(/offline/i);
    expect(section).toContain("auth.sqlite");
  });

  it("states the per-client ceiling on failed case-password guesses across all cases (#2184)", () => {
    expect(section).toMatch(/per client/i);
    expect(section).toMatch(/across all cases/i);
    expect(section).toContain(String(UNLOCK_IP_MAX_FAILURES));
  });
});

describe("the exported N is the one actually used (#2167)", () => {
  it("hashLocalPassword encodes LOCAL_PASSWORD_SCRYPT_N", async () => {
    const encoded = await hashLocalPassword("abcdef");
    expect(encoded.split("$")[1]).toBe(String(LOCAL_PASSWORD_SCRYPT_N));
  });

  it("the timing-equalisation dummy hash tracks LOCAL_PASSWORD_SCRYPT_N", () => {
    const src = readFileSync(new URL("companion/src/auth/authStore.ts", root), "utf8");
    const match = /"scrypt-v1\$(\d+)\$/.exec(src);
    expect(match?.[1]).toBe(String(LOCAL_PASSWORD_SCRYPT_N));
  });

  it("hashCasePassword output matches Node's defaults (stored hashes stay valid)", async () => {
    const { scryptSync } = await import("node:crypto");
    const { salt, hash } = await hashCasePassword("abcdef");
    const nodeDefault = scryptSync("abcdef", Buffer.from(salt, "hex"), 32).toString("hex");
    expect(hash).toBe(nodeDefault);
    expect(CASE_PASSWORD_SCRYPT_N).toBe(16_384);
  });
});
