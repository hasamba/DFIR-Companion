import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3077: a batch regression with the phone category on. An address glued after an encoded blob
// (#3067), a card or another address (#3062) gets its own token before the IPv4 pass, so the phone
// number that starts in its last numbers ("212-555-0123") was never read: the rest of the number went
// out in clear, where it was masked before. Synthetic values only; addresses are built at runtime.

function policy(mask: boolean, IP = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: mask,
    categories: {
      ...{ IP, EMAIL: false, USER: false, HOST: false, DOMAIN: false, PATH: false },
      ...{ CMD: true, REG: true, CARD: true, PHONE: true, NATID: false },
    },
  };
}
const known = (custom: KnownEntities["custom"] = []): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom,
});
const ip = (...p: number[]) => p.join(".");
const BLOB = ["SQBFAFgAIAAo", "AE4AZQB3AC0ATwBi"].join("");
const CARD = ["4111", "1111", "1111", "1111"];
const HEADS: Record<string, string> = {
  blob: `-enc ${BLOB}`,
  card: CARD.join(""),
  "grouped card": CARD.join(" "),
  address: ip(10, 0, 0, 5),
};
const TAILS: Record<string, { tail: string; digits: string[] }> = {
  "dashed phone": { tail: `${ip(10, 0, 0, 212)}-555-0123`, digits: ["555", "0123"] },
  "spaced phone": { tail: `${ip(10, 0, 0, 212)} 555 0123`, digits: ["555", "0123"] },
  "phone from the third number": { tail: `${ip(10, 0, 100, 200)}-5550`, digits: ["5550"] },
};

function fresh(input: string, mask: boolean, IP = true) {
  const a = createAnonymizer(policy(mask, IP), known());
  const out = a.apply(input);
  return { out, back: a.restore(out), saved: a.discoveries() };
}
function seeded(input: string, mask: boolean) {
  const first = fresh(input, mask);
  const a = createAnonymizer(policy(mask), known(first.saved));
  const out = a.apply(input);
  return { out, back: a.restore(out) };
}
const clear = (out: string, digits: string[]) => digits.filter((d) => out.includes(d));

describe("#3077: a phone number after an address glued to a masked value", () => {
  for (const [head, lead] of Object.entries(HEADS))
    for (const [shape, { tail, digits }] of Object.entries(TAILS))
      for (const mask of [false, true]) {
        const input = `x ${lead}${tail} y`;
        it(`${head} + ${shape}, public masking ${mask ? "on" : "off"}: fresh and seeded`, () => {
          const f = fresh(input, mask);
          expect(clear(f.out, digits)).toEqual([]);
          expect(f.back).toBe(input);
          const s = seeded(input, mask);
          expect(clear(s.out, digits)).toEqual([]);
          expect(s.back).toBe(input);
        });
      }

  it("blob + a dotted phone number keeps its last group masked", () => {
    const input = `x -enc ${BLOB}${ip(10, 0, 0, 212)}.555.0123 y`;
    const f = fresh(input, false);
    expect(f.out).not.toContain("0123");
    expect(f.back).toBe(input);
  });

  it("blob + address + phone with the IP category off still masks the phone number", () => {
    const input = `x -enc ${BLOB}${ip(10, 0, 0, 212)}-555-0123 y`;
    const f = fresh(input, false, false);
    expect(clear(f.out, ["555", "0123"])).toEqual([]);
    expect(f.back).toBe(input);
  });

  it("never saves the cut phone number as a discovery", () => {
    const f = fresh(`x ${CARD.join("")}${ip(10, 0, 0, 212)}-555-0123 y`, false);
    expect(f.saved.filter((e) => e.category === "PHONE").map((e) => e.value)).not.toContain("555-0123");
  });

  it("leaves a plain address's earlier-starting number as it was (#3018)", () => {
    const input = `x ${ip(10, 0, 100, 200)}-5550 y`;
    expect(fresh(input, false).out).toContain("-5550");
  });
});
