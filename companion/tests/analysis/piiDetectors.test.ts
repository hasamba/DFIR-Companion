import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };

function policy(over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: false,
    categories: {
      IP: false, EMAIL: false, USER: false, HOST: false, DOMAIN: false,
      PATH: false, CMD: false, REG: false, CARD: false, PHONE: false, NATID: false,
      ...over,
    },
  };
}

describe("CARD detector", () => {
  // Publicly documented test numbers. All Luhn-valid, none issued to anyone.
  it("tokenizes Luhn-valid card numbers with a plausible issuer prefix", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    for (const card of ["4111111111111111", "5500005555555559", "378282246310005"]) {
      const out = a.apply(`charge to ${card} declined`);
      expect(out, card).not.toContain(card);
      expect(out, card).toMatch(/ANON_CARD_\d+/);
      expect(a.restore(out)).toBe(`charge to ${card} declined`);
    }
  });

  it("accepts spaced and dashed groupings", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("card 4111 1111 1111 1111 on file");
    expect(out).not.toContain("4111 1111 1111 1111");
    expect(out).toMatch(/ANON_CARD_1/);
    expect(a.restore(out)).toBe("card 4111 1111 1111 1111 on file");
  });

  it("rejects Luhn-invalid numbers", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("value 4111111111111112 here");
    expect(out).toContain("4111111111111112");
  });

  it("rejects long digit runs with no plausible issuer prefix", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("offset 1234567890123456 bytes");
    expect(out).toContain("1234567890123456");
  });

  it("does nothing when the category is off", () => {
    const a = createAnonymizer(policy(), NONE);
    expect(a.apply("charge to 4111111111111111")).toContain("4111111111111111");
  });
});
