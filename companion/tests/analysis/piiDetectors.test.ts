import { describe, it, expect } from "vitest";
import { createAnonymizer, luhnValid, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

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

  it("accepts spaced and dashed groupings (4-4-4-4)", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("card 4111 1111 1111 1111 on file");
    expect(out).toBe("card ANON_CARD_1 on file");
    expect(a.restore(out)).toBe("card 4111 1111 1111 1111 on file");
  });

  it("accepts the 4-6-5 Amex grouping", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("card 3782 822463 10005 on file");
    expect(out).toBe("card ANON_CARD_1 on file");
    expect(a.restore(out)).toBe("card 3782 822463 10005 on file");
  });

  // Regression test: an earlier version of CARD_RE allowed a separator between EVERY digit
  // (not just at real group boundaries), so two unrelated bare numbers sitting next to each
  // other — a 5-digit field and an 8-digit field, joined by one space — got concatenated into
  // a single 13-digit candidate that happened to pass both the issuer-prefix and Luhn filters.
  // "30001 35174909" -> stripped "3000135174909" -> starts with 3, Luhn-valid -> was wrongly
  // masked. Neither "30001" (5 digits) nor "35174909" (8 digits) is itself a valid card length,
  // and the space between them is not a real 4-4-4-4 / 4-6-5 / 4-4-4-4-3 boundary, so the
  // tightened regex must not match across it at all.
  it("does NOT merge two unrelated adjacent bare numbers into a card candidate", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("field 30001 35174909 recorded");
    expect(out).toBe("field 30001 35174909 recorded");
  });

  it("rejects Luhn-invalid numbers", () => {
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    const out = a.apply("value 4111111111111112 here");
    expect(out).toBe("value 4111111111111112 here");
  });

  // Self-proving: 1234567890123452 is Luhn-VALID (verified below) but starts with "1", which is
  // not a card issuer prefix. The digit run used in an earlier version of this test
  // ("1234567890123456") is Luhn-INVALID on its own, so it was already rejected by the Luhn
  // filter alone — deleting the prefix guard entirely would not have failed that test. This one
  // isolates the prefix filter: only it can be responsible for rejecting a number Luhn would
  // have accepted.
  it("rejects a Luhn-VALID number whose issuer prefix is not a card prefix", () => {
    const notACard = "1234567890123452";
    expect(luhnValid(notACard)).toBe(true); // proves Luhn would have passed it
    const a = createAnonymizer(policy({ CARD: true }), NONE);
    expect(a.apply(`offset ${notACard} bytes`)).toBe(`offset ${notACard} bytes`); // only the prefix filter can be rejecting it
  });

  it("does nothing when the category is off", () => {
    const a = createAnonymizer(policy(), NONE);
    expect(a.apply("charge to 4111111111111111")).toBe("charge to 4111111111111111");
  });
});

describe("PHONE detector", () => {
  it("tokenizes E.164 numbers", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    const out = a.apply("called +972501234567 twice");
    expect(out).not.toContain("+972501234567");
    expect(out).toMatch(/ANON_PHONE_1/);
    expect(a.restore(out)).toBe("called +972501234567 twice");
  });

  it("tokenizes Israeli mobile and landline numbers, dashed or bare", () => {
    for (const phone of ["052-1234567", "0521234567", "03-1234567"]) {
      const a = createAnonymizer(policy({ PHONE: true }), NONE);
      const out = a.apply(`contact ${phone} now`);
      expect(out, phone).not.toContain(phone);
      expect(out, phone).toMatch(/ANON_PHONE_1/);
      expect(a.restore(out)).toBe(`contact ${phone} now`);
    }
  });

  it("tokenizes NANP numbers only when separators are present", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    const out = a.apply("dial 555-123-4567 please");
    expect(out).not.toContain("555-123-4567");
    expect(out).toMatch(/ANON_PHONE_1/);
  });

  it("leaves a bare ten-digit run alone", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("seq 5551234567 done")).toContain("5551234567");
  });

  it("does not fire on dotted quads or timestamps", () => {
    const a = createAnonymizer(policy({ PHONE: true }), NONE);
    expect(a.apply("host 192.168.1.1 up")).toContain("192.168.1.1");
    expect(a.apply("at 2026-07-26 12:00:00")).toContain("2026-07-26");
  });
});
