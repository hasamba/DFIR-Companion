import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type AnonTokenCategory,
  type CustomEntity,
} from "../../src/analysis/anonymize.js";

// #3011: an IPv6 address with a dotted IPv4 tail that #2990 joins whole is saved as a discovery
// (the screenshot OCR pass). On a later call it comes back as a custom value and must not cut a
// longer run ("fd00::10.10.0.0" + ".5") and leave the extra octet in clear. Synthetic values only:
// fd00::/16, 555-01xx and the .invalid TLD.

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

const SAVED = "fd00::10.10.0.0";
const NUM = ["555", "0100"].join("-");
const DOMAIN = ["mail", "invalid"].join(".");

// Call 1 saves the joined address; call 2 runs with it as a custom value.
function saved(mask: boolean): CustomEntity[] {
  const first = make(mask);
  expect(first.apply(`x ${SAVED} y`)).toBe("x ANON_IP_1 y");
  const disc = first.discoveries();
  expect(disc.map((d) => d.value)).toEqual([SAVED]);
  return disc;
}
function second(text: string, mask: boolean, o: Opts = {}) {
  const a = make(mask, { ...o, custom: saved(mask) });
  const out = a.apply(text);
  return { a, out, back: a.restore(out), values: a.pairs().map((p) => p.value) };
}

describe.each([true, false])("a saved IPv6 with a dotted IPv4 tail (#3011), mask=%s", (mask) => {
  describe.each([true, false])("IP category on call 2 = %s", (ip) => {
    const cats = { IP: ip };

    it.each([".5", ".200", ".5.6"])("takes the extra octets %s into one token", (extra) => {
      const input = `x ${SAVED}${extra} y`;
      const r = second(input, mask, { cats });
      expect(r.out).toMatch(/^x ANON_IP_\d+ y$/);
      expect(r.a.restore(r.out.split(" ")[1])).toBe(SAVED + extra);
      expect(r.back).toBe(input);
    });

    it("keeps a port after the longer address", () => {
      const input = `x ${SAVED}.5:443 y`;
      const r = second(input, mask, { cats });
      expect(r.out).toMatch(/^x ANON_IP_\d+:443 y$/);
      expect(r.back).toBe(input);
    });

    it("never saves the longer value", () => {
      const r = second(`x ${SAVED}.5 y`, mask, { cats });
      expect(r.a.discoveries().map((d) => d.value)).not.toContain(`${SAVED}.5`);
    });

    it("leaves the saved address alone when nothing follows it", () => {
      const input = `x ${SAVED} y`;
      const r = second(input, mask, { cats });
      expect(r.out).toBe("x ANON_IP_1 y");
      expect(r.values).toEqual([SAVED]);
    });
  });

  it("keeps the email reading when the extra octet opens an email address", () => {
    const input = `x ${SAVED}.5@${DOMAIN} y`;
    const r = second(input, mask, { cats: { EMAIL: true } });
    expect(r.out).not.toMatch(/\.5@/);
    expect(r.out).not.toContain(DOMAIN);
    expect(r.back).toBe(input);
  });

  it("splits a phone number that starts in the extra octet", () => {
    const input = `x ${SAVED}.100 ${NUM} y`;
    const r = second(input, mask, { cats: { PHONE: true } });
    expect(r.out).toMatch(/^x ANON_IP_\d+ ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
  });

  // The longer value is minted forced, like the existing late join: the saved shorter value is
  // masked anyway, so a suppression of the longer one cannot uncover anything.
  it("masks the longer value even when it is suppressed", () => {
    const input = `x ${SAVED}.5 y`;
    const r = second(input, mask, { suppressed: [`${SAVED}.5`] });
    expect(r.out).toMatch(/^x ANON_IP_\d+ y$/);
    expect(r.a.restore(r.out.split(" ")[1])).toBe(`${SAVED}.5`);
    expect(r.back).toBe(input);
  });
});
