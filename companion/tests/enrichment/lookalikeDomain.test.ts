import { describe, it, expect } from "vitest";
import { LookalikeDomainProvider } from "../../src/enrichment/lookalikeDomain.js";

const p = new LookalikeDomainProvider();

describe("LookalikeDomainProvider", () => {
  it("is a local (offline, OPSEC-safe) provider that only supports domains", () => {
    expect(p.scope).toBe("local");
    expect(p.supports("domain")).toBe(true);
    expect(p.supports("ip")).toBe(false);
    expect(p.supports("hash")).toBe(false);
  });

  it("returns a suspicious verdict with a brand tag for a lookalike domain", async () => {
    const r = await p.lookup("domain", "paypa1.com");
    expect(r).not.toBeNull();
    expect(r?.verdict).toBe("suspicious");
    expect(r?.source).toBe("Lookalike Domain");
    expect(r?.tags).toEqual(expect.arrayContaining(["Homoglyph domain", "similar to paypal.com"]));
    expect(r?.score).toMatch(/homoglyph/i);
  });

  it("returns null (checked, clean) for a legitimate domain", async () => {
    expect(await p.lookup("domain", "microsoft.com")).toBeNull();
    expect(await p.lookup("domain", "example.com")).toBeNull();
  });

  it("returns null for a non-domain kind", async () => {
    expect(await p.lookup("ip", "1.2.3.4")).toBeNull();
  });
});
