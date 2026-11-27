import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type AnonTokenCategory,
  type CustomEntity,
} from "../../src/analysis/anonymize.js";

// #3012: a fifth (or later) dotted number after an IPv6 address with a dotted IPv4 tail, or after
// an address left in clear, must not reach the AI in clear. Synthetic values only: fd00::/16,
// 2001:db8::/32, 10/8, 555-01xx and the .invalid TLD. Anything public-looking is built at runtime.

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
type Opts = { cats?: Cats; custom?: CustomEntity[]; suppressed?: string[] };
const make = (mask: boolean, o: Opts = {}) =>
  createAnonymizer(policy(mask, o.cats ?? {}), {
    hosts: [],
    accounts: [],
    internalDomains: [],
    custom: o.custom ?? [],
    suppressed: o.suppressed ?? [],
  });

const NUM = ["555", "0100"].join("-");
const DOMAIN = ["mail", "invalid"].join(".");
const PUBLIC_V4 = [203, 0, 113, 7].join(".");
const FIVE = /\d+\.\d+\.\d+\.\d+\.\d+$/;

function run(text: string, mask: boolean, o: Opts = {}) {
  const a = make(mask, o);
  const out = a.apply(text);
  return { a, out, back: a.restore(out), saved: a.discoveries().map((d) => d.value) };
}
// The digits left once every token is taken out (the "x"/"y" context holds none).
const clearDigits = (out: string) => out.replace(/ANON_[A-Z]+_\d+/g, "").replace(/\D/g, "");

describe.each([true, false])("a fifth dotted number after an IPv6 address (#3012), mask=%s", (mask) => {
  describe("shape 1: an IPv4-mapped address (::ffff:)", () => {
    it.each([".6", ".6.7"])("masks the extra numbers %s with the address", (extra) => {
      const input = `x ::ffff:10.0.0.5${extra} y`;
      const r = run(input, mask);
      expect(r.out).toBe("x ANON_IP_2 y");
      expect(r.a.restore("ANON_IP_2")).toBe(`::ffff:10.0.0.5${extra}`);
      expect(r.back).toBe(input);
      expect(r.saved).toContain("::ffff:10.0.0.5");
      expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
    });

    it("splits a phone number that starts in the extra number", () => {
      const input = `x ::ffff:10.0.0.5.100 ${NUM} y`;
      const r = run(input, mask, { cats: { PHONE: true } });
      expect(r.out).toBe("x ANON_IP_2 ANON_PHONE_1 y");
      expect(r.back).toBe(input);
      expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
    });

    it("keeps the email reading when the extra number opens an email address", () => {
      const input = `x ::ffff:10.0.0.5.6@${DOMAIN} y`;
      const r = run(input, mask, { cats: { EMAIL: true } });
      expect(r.out).not.toContain(DOMAIN);
      expect(clearDigits(r.out)).toBe("");
      expect(r.back).toBe(input);
    });
  });

  describe("shape 1b: an internal address whose last four numbers are not an address", () => {
    it.each(["fd00::10.0.0.5.6", "fd00::1:10.0.0.5.6", "fd00::ffff:10.0.0.5.6"])(
      "masks %s as one token",
      (value) => {
        const input = `x ${value} y`;
        const r = run(input, mask);
        expect(r.out).toMatch(/^x ANON_IP_\d+ y$/);
        expect(r.a.restore(r.out.split(" ")[1])).toBe(value);
        expect(r.back).toBe(input);
        expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
      },
    );

    it("masks a sixth number too", () => {
      const input = "x fd00::10.10.0.0.5.6 y";
      const r = run(input, mask);
      expect(r.out).toMatch(/^x ANON_IP_\d+ y$/);
      expect(r.back).toBe(input);
      expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
    });
  });

  describe("shape 3: a phone number after a fifth number", () => {
    it("keeps the phone number masked", () => {
      const input = `x fd00::10.10.0.0.100 ${NUM} y`;
      const r = run(input, mask, { cats: { PHONE: true } });
      expect(r.out).toBe("x ANON_IP_1.ANON_IP_2 ANON_PHONE_1 y");
      expect(r.back).toBe(input);
    });

    it("leaves a plain IPv4 before a phone number as it was", () => {
      const input = `x 10.0.0.100 ${NUM} y`;
      const r = run(input, mask, { cats: { PHONE: true } });
      expect(r.out).toBe(`x ANON_IP_1 ${NUM} y`);
      expect(r.back).toBe(input);
    });
  });

  it("masks a public mapped address and its extra number with public masking on", () => {
    if (!mask) return;
    const input = `x ::ffff:${PUBLIC_V4}.6 y`;
    const r = run(input, mask);
    expect(r.out).toMatch(/^x ANON_EXTIP_\d+ y$/);
    expect(r.back).toBe(input);
  });

  it("masks a fifth number after a bare :: prefix", () => {
    const input = "x ::10.0.0.5.6 y";
    const r = run(input, mask);
    expect(r.out).toBe("x ::ANON_IP_2 y");
    expect(r.a.restore("ANON_IP_2")).toBe("10.0.0.5.6");
    expect(r.back).toBe(input);
    expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
  });

  it("leaves a plain five-number run as it was", () => {
    const input = "x 10.10.0.0.5 y";
    const r = run(input, mask);
    expect(r.out).toBe("x ANON_IP_1.5 y");
    expect(r.back).toBe(input);
  });

  // Like the #3011 join, the longer value is minted forced: the head is masked anyway.
  it("masks the longer value even when it is suppressed", () => {
    const input = "x fd00::10.0.0.5.6 y";
    const r = run(input, mask, { suppressed: ["fd00::10.0.0.5.6"] });
    expect(r.out).toMatch(/^x ANON_IP_\d+ y$/);
    expect(r.back).toBe(input);
  });
});

describe("shape 2: a fifth number after a public address left in clear (#3012)", () => {
  it("masks the dotted numbers as one token", () => {
    const input = "x 2001:db8::10.10.0.0.5 y";
    const r = run(input, false);
    expect(r.out).toBe("x 2001:db8::ANON_IP_2 y");
    expect(r.a.restore("ANON_IP_2")).toBe("10.10.0.0.5");
    expect(r.back).toBe(input);
    expect(r.saved).toContain("10.10.0.0");
    expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
  });

  it("keeps every digit masked with public masking on", () => {
    const input = "x 2001:db8::10.10.0.0.5 y";
    const r = run(input, true);
    expect(r.out).toMatch(/^x [^ ]+ y$/);
    expect(r.out.replace(/ANON_[A-Z]+_\d+/g, "")).toBe("x . y");
    expect(r.back).toBe(input);
  });

  it("splits a phone number that starts in the fifth number", () => {
    const input = `x 2001:db8::10.10.0.0.100 ${NUM} y`;
    const r = run(input, false, { cats: { PHONE: true } });
    expect(r.out).toBe("x 2001:db8::ANON_IP_2 ANON_PHONE_1 y");
    expect(r.back).toBe(input);
  });

  describe.each([true, false])("a plain run seeded with a saved IPv4, IP category = %s", (ip) => {
    it.each(["x 10.10.0.0.5 y", "x 10.10.0.0.5.6 y"])("leaves %s as it was", (input) => {
      const first = run("x 10.10.0.0 y", false);
      const seeded = run(input, false, { cats: { IP: ip }, custom: first.a.discoveries() });
      expect(seeded.out).toMatch(/^x ANON_IP_1\.5/);
      expect(seeded.back).toBe(input);
    });
  });

  describe.each([true, false])("a seeded second call, IP category = %s", (ip) => {
    it.each(["x 2001:db8::10.10.0.0.5 y", "x fd00::10.0.0.5.6 y", "x ::ffff:10.0.0.5.6 y"])(
      "masks %s at least as much as a fresh call",
      (input) => {
        const first = run(input, false);
        const custom = first.a.discoveries();
        expect(custom.some((d) => FIVE.test(d.value))).toBe(false);
        const seeded = run(input, false, { cats: { IP: ip }, custom });
        const fresh = run(input, false, { cats: { IP: ip } });
        expect(seeded.back).toBe(input);
        expect(clearDigits(seeded.out).length).toBeLessThanOrEqual(clearDigits(fresh.out).length);
        expect(seeded.saved.some((v) => FIVE.test(v))).toBe(false);
      },
    );
  });
});
