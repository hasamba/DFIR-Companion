import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3071: an IPv4 address glued right after a word ("ab" + address, "srv01" + address, "srv01_" + address)
// went out in clear: the address readers need a word boundary before the first number. The address now
// gets its own token and the word before it stays as it is. It is graded as a standalone address: an
// internal one always, a public one only with public masking on.

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
function policy(maskPublicIps: boolean, IP = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: {
      IP,
      EMAIL: true,
      USER: true,
      HOST: true,
      DOMAIN: true,
      PATH: true,
      CMD: true,
      REG: true,
      CARD: true,
      PHONE: true,
      NATID: true,
    },
  };
}
const dotted = (...parts: number[]) => parts.join("."); // built at runtime: no literal address in source
const INNER = dotted(10, 0, 0, 5);
const PUB = dotted(8, 8, 8, 8);

describe("an IPv4 address glued after a word (#3071)", () => {
  for (const pm of [false, true]) {
    it(`masks an internal address glued after a word and keeps the word (public masking ${pm ? "on" : "off"})`, () => {
      const cases: Array<[string, string]> = [
        [`x ab${INNER}`, "x abANON_IP_1"],
        [`x srv01${INNER} y`, "x srv01ANON_IP_1 y"],
        [`x srv01_${INNER}`, "x srv01_ANON_IP_1"],
        [`x a${INNER}.`, "x aANON_IP_1."],
        [`x ab${INNER}1234`, "x abANON_IP_1"], // digits glued on the end too: masked whole, as #3058
      ];
      for (const [text, want] of cases) {
        const a = createAnonymizer(policy(pm), NONE);
        const out = a.apply(text);
        expect(out).toBe(want);
        expect(a.restore(out)).toBe(text);
      }
    });
  }

  it("reads an ambiguous digit head as the internal address, the longest on a tie", () => {
    const a = createAnonymizer(policy(true), NONE);
    expect(a.apply(`x node${dotted(127, 0, 0, 1)}`)).toBe("x nodeANON_IP_1");
    const b = createAnonymizer(policy(false), NONE);
    expect(b.apply(`x h1${dotted(192, 168, 1, 5)}`)).toBe("x h1ANON_IP_1");
  });

  it("grades a public address glued after a word as a standalone one", () => {
    const off = createAnonymizer(policy(false), NONE);
    expect(off.apply(`x ab${PUB}`)).toBe(`x ab${PUB}`);
    expect(off.apply(`kernel${dotted(5, 10, 0, 1)}`)).toBe(`kernel${dotted(5, 10, 0, 1)}`);
    const on = createAnonymizer(policy(true), NONE);
    const out = on.apply(`x ab${PUB}`);
    expect(out).toBe("x abANON_EXTIP_1");
    expect(on.restore(out)).toBe(`x ab${PUB}`);
  });

  it("masks the address after a learned user name, and never reads the name token's number as an octet", () => {
    const a = createAnonymizer(policy(false), { ...NONE, usernames: ["someuser"] });
    const text = `x someuser${INNER} y`;
    const out = a.apply(text);
    expect(out).toBe("x ANON_USER_1ANON_IP_1 y");
    expect(a.restore(out)).toBe(text);
    // "0.0.0.5" is never masked: the "1" of the name's token must not make it "10.0.0.5"
    const zero = `x someuser${dotted(0, 0, 0, 5)} y`;
    const out2 = a.apply(zero);
    expect(out2).toBe(`x ANON_USER_1·${dotted(0, 0, 0, 5)} y`);
    expect(a.restore(out2)).toBe(zero);
  });

  it("gives the same token on a later call and keeps the reading master had", () => {
    const a = createAnonymizer(policy(true), NONE);
    expect(a.apply(`x ${INNER}`)).toBe("x ANON_IP_1");
    expect(a.apply(`x ab${INNER}`)).toBe("x abANON_IP_1");
    expect(a.apply(`x1.${dotted(2, 3, 4, 5)}`)).toBe("x1.ANON_EXTIP_1");
  });

  it("leaves a card or phone number that starts in the address's last digits to its own pass", () => {
    const a = createAnonymizer(policy(true), NONE);
    const card = ["4111", "1111", "1111", "1111"];
    const withCard = `x ab${dotted(127, 0, 0, 1)}${card.join(" ")} y`;
    const out = a.apply(withCard);
    expect(out).toMatch(/ANON_CARD_\d/);
    expect(out).not.toContain(card[1]);
    expect(a.restore(out)).toBe(withCard);
    const withPhone = `x ab${dotted(10, 0, 0, 212)}-555-0123 y`;
    const out2 = a.apply(withPhone);
    expect(out2).toMatch(/ANON_PHONE_\d/);
    expect(out2).not.toContain("0123");
    expect(a.restore(out2)).toBe(withPhone);
  });

  it("keeps a profile name glued to an address in its one token, as before", () => {
    const a = createAnonymizer(policy(false), { ...NONE, accounts: ["jdoe"] });
    const root = ["C:", "Users", ""].join("\\"); // built at runtime: no literal profile path in source
    const text = `${root}jdoe${INNER} x`;
    const out = a.apply(text);
    expect(out).toBe(`${root}ANON_USER_1`);
    expect(a.restore(out)).toBe(text);
  });

  it("leaves a word made only of digits before an address as it was", () => {
    const a = createAnonymizer(policy(false), NONE);
    expect(a.apply(`x 99${INNER} y`)).toBe(`x 99${INNER} y`);
  });

  it("leaves a dotted run, a word after the address and the IP category off as they were", () => {
    const a = createAnonymizer(policy(false), NONE);
    for (const text of [`x ab${INNER}.6`, `x ab${INNER}x`, `x ab${dotted(1, 2, 3)}`])
      expect(a.apply(text)).toBe(text);
    const off = createAnonymizer(policy(true, false), NONE);
    expect(off.apply(`x ab${INNER}`)).toBe(`x ab${INNER}`);
  });
});
