import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type AnonTokenCategory,
  type CustomEntity,
} from "../../src/analysis/anonymize.js";

// #3018: a plain run of five or more dotted numbers whose first four are an IPv4 address the IPv4
// pass masks is one token, and a phone number after a plain IPv4 keeps its own token. Synthetic
// values only: 10/8, 192.168/16, 555-01xx. Anything public-looking is built at runtime.

type Cats = Partial<Record<AnonTokenCategory, boolean>>;
function policy(mask: boolean, cats: Cats): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: mask,
    categories: {
      IP: true,
      EMAIL: false,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE: false,
      NATID: false,
      ...cats,
    },
  };
}
type Opts = { cats?: Cats; custom?: CustomEntity[] };
function run(text: string, mask: boolean, o: Opts = {}) {
  const a = createAnonymizer(policy(mask, o.cats ?? {}), {
    hosts: [],
    accounts: [],
    internalDomains: [],
    custom: o.custom ?? [],
    suppressed: [],
  });
  const out = a.apply(text);
  return { a, out, back: a.restore(out), saved: a.discoveries().map((d) => d.value) };
}

const NUM = ["555", "0100"].join("-");
const OID = [1, 3, 6, 1, 4, 1].join("."); // an SNMP OID that starts like a public IPv4
const OID_HEAD = OID.split(".").slice(0, 4).join(".");
const FIVE = /\d+\.\d+\.\d+\.\d+\.\d+/;
// The numbers left once every token is taken out.
const clearNums = (out: string) => out.replace(/ANON_[A-Z]+_\d+/g, "").replace(/\D/g, "");

describe.each([true, false])("a plain dotted run (#3018), mask=%s", (mask) => {
  it.each(["x 10.10.0.0.5.6 y", "x 192.168.1.5.0 y", "host.10.10.0.0.5 y"])("masks %s whole", (input) => {
    const r = run(input, mask);
    expect(r.out.replace(/ANON_IP_\d+/, "T")).toMatch(/^(x |host\.)T y$/);
    expect(r.back).toBe(input);
    expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
  });

  it("keeps every address the IPv4 pass saved inside a longer run", () => {
    const input = "x 10.0.0.5.10.0.0.6 y";
    const r = run(input, mask);
    expect(r.out).toMatch(/^x ANON_IP_\d+ y$/);
    expect(r.back).toBe(input);
    expect(r.saved).toEqual(expect.arrayContaining(["10.0.0.5", "10.0.0.6"]));
    expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
  });

  it("keeps the inner address saved for a longer run after a bare ::", () => {
    const input = "x ::10.0.0.5.10.0.0.6 y";
    const r = run(input, mask);
    expect(r.out).toMatch(/^x ::ANON_IP_\d+ y$/);
    expect(r.back).toBe(input);
    expect(r.saved).toEqual(expect.arrayContaining(["10.0.0.5", "10.0.0.6"]));
  });

  it("follows the public-masking setting for a run that starts with a public address", () => {
    const input = `x ${OID} y`;
    const r = run(input, mask);
    if (mask) {
      expect(r.out).toMatch(/^x ANON_EXTIP_\d+ y$/);
      expect(r.saved).toContain(OID_HEAD);
    } else expect(r.out).toBe(input);
    expect(r.back).toBe(input);
    expect(r.saved).not.toContain(OID);
  });

  it.each([
    ["x 300.10.0.0.5 y", "x 300.10.0.0.5 y"],
    ["abc10.10.0.0.5", "abc10.ANON_IP_1"],
    ["x 10.0.0.5.6a y", "x ANON_IP_1.6a y"],
    ["x 10.0.0.5.1234 y", "x ANON_IP_1.1234 y"],
  ])("reads %s the way the IPv4 pass does", (input, want) => {
    const r = run(input, mask);
    expect(r.out).toBe(want);
    expect(r.back).toBe(input);
  });

  it("leaves digits alone that are not a phone number starting in the last number", () => {
    const r = run("x 10.0.100.200 4624 y", mask, { cats: { PHONE: true } });
    expect(r.out).toBe("x ANON_IP_1 4624 y");
  });

  it("masks a phone number after a run's fifth number", () => {
    const input = `x 10.10.0.0.100 ${NUM} y`;
    const r = run(input, mask, { cats: { PHONE: true } });
    expect(r.out).toBe("x ANON_IP_2 ANON_PHONE_1 y");
    expect(r.back).toBe(input);
  });

  describe.each([true, false])("a seeded second call, IP category = %s", (ip) => {
    it.each([
      ["x 10.0.0.100 y", `x 10.0.0.100 ${NUM} y`],
      [`x 10.0.0.100 ${NUM} y`, `x 10.0.0.100 ${NUM} y`],
      ["x 10.10.0.0.5 y", "x 10.10.0.0.5 y"],
      ["x 10.10.0.0 y", "x 10.10.0.0.5.6 y"],
    ])("after %s, keeps every number of %s masked", (first, input) => {
      const one = run(first, mask, { cats: { PHONE: true } });
      const custom = one.a.discoveries();
      expect(custom.some((d) => FIVE.test(d.value))).toBe(false);
      const seeded = run(input, mask, { cats: { IP: ip, PHONE: true }, custom });
      expect(clearNums(seeded.out)).toBe("");
      expect(seeded.back).toBe(input);
      expect(seeded.saved.some((v) => FIVE.test(v))).toBe(false);
    });

    it("never saves a phone number read across a plain IPv4, so it cannot cut another address", () => {
      const one = run(`x 10.0.0.100 ${NUM} y`, mask, { cats: { PHONE: true } });
      expect(one.saved).not.toContain(`100 ${NUM}`);
      const input = `x 192.168.1.100 ${NUM} y`;
      const seeded = run(input, mask, { cats: { IP: ip, PHONE: true }, custom: one.a.discoveries() });
      // With the IP category off, addresses are not masked at all: the seeded call matches a fresh one.
      if (ip) expect(seeded.out).not.toContain("192.168.1.");
      else expect(seeded.out).toBe(run(input, mask, { cats: { IP: ip, PHONE: true } }).out);
      expect(seeded.back).toBe(input);
    });
  });

  it("keeps the inner address saved when a saved IPv4 takes a longer run", () => {
    const one = run("x 10.0.0.5 y", mask);
    const input = "x 10.0.0.5.10.0.0.6 y";
    const seeded = run(input, mask, { custom: one.a.discoveries() });
    expect(seeded.out).toMatch(/^x ANON_IP_\d+ y$/);
    expect(seeded.back).toBe(input);
    expect(seeded.saved).toContain("10.0.0.6");
  });
});
