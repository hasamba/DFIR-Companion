import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type AnonTokenCategory,
  type CustomEntity,
} from "../../src/analysis/anonymize.js";

// #3027: a seeded call (one that re-injects saved values) never masks less than the same call
// without them, when a phone number follows the address. Synthetic values only: 10/8, fd00::/8,
// 2001:db8::/32 and 555-01xx, built at runtime.

type Cats = Partial<Record<AnonTokenCategory, boolean>>;
function policy(mask: boolean, cats: Cats): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: mask,
    categories: {
      IP: true,
      EMAIL: true,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE: true,
      NATID: false,
      ...cats,
    },
  };
}
function anon(mask: boolean, cats: Cats, custom: CustomEntity[] = []) {
  return createAnonymizer(policy(mask, cats), {
    hosts: [],
    accounts: [],
    internalDomains: [],
    custom,
    suppressed: [],
  });
}
function seeded(first: string, second: string, mask: boolean, cats: Cats = {}) {
  const a = anon(mask, {});
  a.apply(first);
  const s = anon(mask, cats, a.discoveries());
  const out = s.apply(second);
  return { out, back: s.restore(out) };
}
function fresh(text: string, mask: boolean, cats: Cats = {}) {
  const a = anon(mask, cats);
  const out = a.apply(text);
  return { out, back: a.restore(out) };
}

const NUM = ["555", "0100"].join("-");
const DOC = ["2001", "db8::"].join(":");
// The digits left in clear once every token is taken out.
const clear = (out: string) => out.replace(/ANON_[A-Z]+_\d+/g, "").replace(/\D/g, "");

describe.each([false, true])("a seeded call with a phone number masks no less (#3027), mask=%s", (mask) => {
  it("shape 1: a saved address with a dotted tail splits the phone number after it", () => {
    for (const head of ["fd00::", "fd00::a:"]) {
      const addr = `${head}10.0.0.100`;
      const input = `x ${addr} ${NUM} y`;
      const r = seeded(`x ${addr} y`, input, mask);
      expect(r.out).toMatch(/^x ANON_IP_\d+ ANON_PHONE_\d+ y$/);
      expect(r.back).toBe(input);
    }
  });

  it("shape 1: a saved plain IPv4 inside the address splits the phone number after it", () => {
    const input = `x fd00::10.0.0.100 ${NUM} y`;
    for (const first of ["x 10.0.0.100 4624 y", "x 10.0.0.100:443 y", `x 10.0.0.100 ${NUM} y`]) {
      const r = seeded(first, input, mask);
      expect(r.out).toMatch(/^x ANON_IP_\d+ ANON_PHONE_\d+ y$/);
      expect(r.back).toBe(input);
    }
  });

  it("shape 2: a saved phone value with a dotted lead behind an address left in clear", () => {
    const input = `x ${DOC}10.10.0.0.100 ${NUM} y`;
    const r = seeded(`x 10.0.0.100.100 ${NUM} y`, input, mask);
    expect(clear(r.out.replace(DOC, "")).length).toBe(0);
    if (!mask) {
      expect(r.out.startsWith(`x ${DOC}`)).toBe(true);
      expect(r.out.slice(2 + DOC.length)).toMatch(/^ANON_IP_\d+ ANON_PHONE_\d+ y$/);
    }
    expect(r.back).toBe(input);
  });

  it("shape 2: the run is never saved as one value", () => {
    const input = `x ${DOC}10.10.0.0.100 ${NUM} y`;
    const a = anon(mask, {});
    a.apply(`x 10.0.0.100.100 ${NUM} y`);
    const s = anon(mask, {}, a.discoveries());
    s.apply(input);
    expect(s.discoveries().some((e) => /\d+\.\d+\.\d+\.\d+\.\d+/.test(e.value))).toBe(false);
  });

  it("shape 1: also with the IP category off on the seeded call", () => {
    const input = `x fd00::10.0.0.100 ${NUM} y`;
    const r = seeded("x fd00::10.0.0.100 y", input, mask, { IP: false });
    expect(clear(r.out).length).toBeLessThanOrEqual(clear(fresh(input, mask, { IP: false }).out).length);
    expect(r.out).not.toContain(NUM);
    expect(r.back).toBe(input);
  });

  it("shape 1: a number that does not start in the last octet is left as before", () => {
    const input = "x fd00::10.0.0.100 4624 y";
    const r = seeded("x fd00::10.0.0.100 y", input, mask);
    expect(r.out).toMatch(/^x ANON_IP_\d+ 4624 y$/);
    expect(r.back).toBe(input);
  });

  it("shape 1: the phone category off leaves the number in clear, as a fresh call does", () => {
    const input = `x fd00::10.0.0.100 ${NUM} y`;
    const r = seeded("x fd00::10.0.0.100 y", input, mask, { PHONE: false });
    expect(r.out).toBe(fresh(input, mask, { PHONE: false }).out);
    expect(r.back).toBe(input);
  });

  it("keeps a documentation-prefix address with a dotted tail as before", () => {
    const input = `x ${DOC}10.0.0.100 ${NUM} y`;
    const r = seeded(`x ${DOC}10.0.0.100 y`, input, mask);
    expect(clear(r.out).length).toBeLessThanOrEqual(clear(fresh(input, mask).out).length);
    expect(r.back).toBe(input);
  });
});
