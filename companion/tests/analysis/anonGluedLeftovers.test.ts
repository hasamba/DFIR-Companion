import { describe, expect, it } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3078 — glued-address leftovers. (1) A token glued before a value that stays in clear (suppressed)
// keeps the restore exact. (2) An address glued after a word and followed by ".<digit>", or after a
// word made only of digits, is masked. (3) A phone number that starts in the last number of a
// word-glued address leaves no part of the address in clear. Addresses and cards built at runtime.

function policy(maskPublicIps = true, over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: {
      ...{ IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true },
      ...{ CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
      ...over,
    },
  };
}
const ip = (...parts: Array<number | string>) => parts.join(".");
const known = (suppressed: string[] = []): KnownEntities => ({
  ...{ hosts: [], accounts: [], internalDomains: [], usernames: [] },
  suppressed,
});
const A1 = ip(10, 0, 0, 5);
const A2 = ip(10, 0, 212, 155);
const CARD16 = ["4111", "1111", "1111", "1111"].join("");
const CARD = ["4111", "1111", "1111", "1111"].join(" ");
const PHONE_TAIL = ["555", "0123"].join("-");

function run(text: string, mask: boolean, suppressed: string[] = [], over = {}) {
  const a = createAnonymizer(policy(mask, over), known(suppressed));
  const out = a.apply(text);
  return { out, back: a.restore(out) };
}

describe("#3078 claim 1: a token glued before a suppressed value", () => {
  const rows: Array<[string, string, string]> = [
    ["two addresses, the second suppressed", `x ${A1}${A2}`, A2],
    ["two addresses, the first suppressed", `x ${A1}${A2}`, A1],
    ["a card then a suppressed address", `x ${CARD16}${A1}`, A1],
    ["an address then a suppressed card", `x ${A1}${CARD16}`, CARD16],
    ["a grouped card then a suppressed address", `x ${CARD}${A1}`, A1],
    ["an address then a suppressed grouped card", `x ${A1}${CARD}`, CARD],
  ];
  for (const mask of [true, false])
    for (const [name, text, sup] of rows)
      it(`${name} round-trips exactly (public masking ${mask ? "on" : "off"})`, () => {
        const { out, back } = run(text, mask, [sup]);
        expect(back).toBe(text);
        expect(out).toContain(sup); // the suppressed value is kept verbatim
        expect(out).toMatch(/ANON_(IP|CARD)_\d+/); // the other part is still masked
      });
});

describe("#3078 claim 2: an address glued after a word with a dotted tail, or after digits", () => {
  for (const mask of [true, false]) {
    it(`a dotted tail after a word-glued address is masked with it (masking ${mask})`, () => {
      for (const text of [`x ab${A1}.6`, `ab${A1}.6`, `srv01${A1}.6.7`]) {
        const { out, back } = run(text, mask);
        expect(back).toBe(text);
        expect(out).not.toMatch(/\d\.\d/); // no dotted number left in clear
        expect(out).toMatch(/^(x )?(ab|srv01)ANON_IP_\d+$/);
      }
    });
    it(`an address glued after a digit-only word is masked with the digits (masking ${mask})`, () => {
      for (const text of [`x 12${A1}`, `45${A1}`, `x 999${A1}`, `x 01${A1}`]) {
        const { out, back } = run(text, mask);
        expect(back).toBe(text);
        expect(out).toMatch(/^(x )?ANON_IP_\d+$/);
      }
    });
  }
  it("a longer digit run, one after a number group, or one the IPv4 pass read is left as it was", () => {
    for (const text of [`x 12345${A1}`, `x 1111 22${A1}`, `x 3${A1}`]) expect(run(text, true).out).toBe(text);
  });
  it("a public address after a word with a dotted tail stays clear with public masking off", () => {
    const text = `x ab${ip(8, 8, 8, 8)}.6`;
    expect(run(text, false).out).toBe(text);
  });
});

describe("#3078 claim 3: a phone number that starts in the last number of a word-glued address", () => {
  const text = `x ab${ip(10, 0, 0, 212)}-${PHONE_TAIL}`;
  for (const mask of [true, false])
    it(`leaves no number of the address in clear (masking ${mask})`, () => {
      const { out, back } = run(text, mask);
      expect(back).toBe(text);
      expect(out).toMatch(/^x abANON_IP_\d+-ANON_PHONE_\d+$/);
    });
  it("with the PHONE category off the address is still masked", () => {
    const { out, back } = run(text, true, [], { PHONE: false });
    expect(back).toBe(text);
    expect(out).toBe(`x abANON_IP_1-${PHONE_TAIL}`);
  });
});
