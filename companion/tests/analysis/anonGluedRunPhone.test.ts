import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3066: two batch regressions with the phone category on.
// 1. Public masking off: an IPv4-mapped IPv6 whose public IPv4 ends in ".100", then ".100.555.0100".
//    The glued-IPv4 reading (#3058) took four numbers in the middle of the run as one address and
//    left the phone number's last group in clear; before, the phone number was masked.
// 2. Public masking on, seeded: call 1 saved a dotted phone value ("100.555.0100") that starts in
//    the last number of a private address; on call 2 that saved value cut the address, and its first
//    three numbers went out in clear; before, the address was masked.
// Synthetic values only; addresses are built at runtime.

function policy(mask: boolean, REG = true, IP = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: mask,
    categories: {
      IP,
      EMAIL: false,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG,
      CARD: false,
      PHONE: true,
      NATID: false,
    },
  };
}
const known = (custom: KnownEntities["custom"] = []): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom,
});
const SID = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const PUB = ["198", "51", "100", "100"].join("."); // a documentation range address
const PRIV = ["192", "168", "1", "100"].join(".");
const PHONE_REST = [".100", "555", "0100"].join(".");

function fresh(input: string, mask: boolean, REG = true) {
  const a = createAnonymizer(policy(mask, REG), known());
  const out = a.apply(input);
  return { out, back: a.restore(out), saved: a.discoveries() };
}
function seeded(first: string, input: string, mask: boolean, REG = true) {
  const seed = createAnonymizer(policy(mask, REG), known());
  seed.apply(first);
  const a = createAnonymizer(policy(mask, REG), known(seed.discoveries()));
  const out = a.apply(input);
  return { out, back: a.restore(out) };
}

describe("#3066 shape 1: a glued-IPv4 reading inside a longer dotted run", () => {
  for (const lead of ["", SID]) {
    const input = `x ${lead}::ffff:${PUB}${PHONE_REST} y`;
    it(`masks the phone number's last group (${lead ? "after a SID" : "alone"}), fresh`, () => {
      const r = fresh(input, false);
      expect(r.out).not.toContain("0100");
      expect(r.out).not.toContain("555");
      expect(r.back).toBe(input);
    });
    it(`masks it on a seeded call too (${lead ? "after a SID" : "alone"})`, () => {
      const r = seeded(input, input, false);
      expect(r.out).not.toContain("0100");
      expect(r.out).not.toContain("555");
      expect(r.back).toBe(input);
    });
  }
  it("never saves the run with the numbers after the glued reading", () => {
    const r = fresh(`x ::ffff:${PUB}${PHONE_REST} y`, false);
    const values = r.saved.map((e) => e.value);
    expect(values.some((v) => v.endsWith(".0100"))).toBe(false);
  });
  it("leaves a glued IPv4 that starts a run as before", () => {
    const input = `x ${["10", "0", "0", "1234"].join(".")} y`;
    const r = fresh(input, false);
    expect(r.out).toBe("x ANON_IP_1 y");
    expect(r.back).toBe(input);
  });
});

describe("#3066 shape 2: a saved dotted phone value that starts in an address's last number", () => {
  const first = `x ${SID}${PRIV}${PHONE_REST} y`;
  const input = `x ${PRIV}.555.0100 y`;
  for (const REG of [true, false]) {
    it(`masks the whole address and the rest of the number, REG ${REG ? "on" : "off"}`, () => {
      const r = seeded(first, input, true, REG);
      expect(r.out).toMatch(/^x ANON_IP_\d+\.ANON_PHONE_\d+ y$/);
      expect(r.back).toBe(input);
    });
  }
  it("masks the same with public masking off", () => {
    const r = seeded(first, input, false);
    expect(r.out).toMatch(/^x ANON_IP_\d+\.ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
  });
  it("matches a fresh call's shape", () => {
    expect(fresh(input, true).out).toMatch(/^x ANON_IP_\d+\.ANON_PHONE_\d+ y$/);
  });
});
