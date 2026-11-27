import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3033: IPV6_RE reads an IPv4-mapped address ("::ffff:10.0.0.100") in one piece, so no dotted tail
// is cut and joined, and a phone number that starts in its last number ("100 555-0100") left the
// rest of the number in clear. An "fd00::" address is split: the address, then the rest of the
// number as its own token. Synthetic values only.

function policy(maskPublicIps: boolean, PHONE = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
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
      PHONE,
      NATID: false,
    },
  };
}
const known = (suppressed: string[] = []): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  custom: [],
  suppressed,
});

function run(input: string, mask: boolean, PHONE = true, suppressed: string[] = []) {
  const a = createAnonymizer(policy(mask, PHONE), known(suppressed));
  const out = a.apply(input);
  const tokens = out.match(/ANON_[A-Z]+_\d+/g) ?? [];
  return {
    out,
    values: tokens.map((t) => a.restore(t)),
    back: a.restore(out),
    saved: a.discoveries().map((e) => `${e.category}:${e.value}`),
  };
}

const MAPPED = "::ffff:10.0.0.100";
const PHONE_REST = "555-0100";
// A documentation-range address, built at runtime.
const PUBLIC_MAPPED = "::ffff:" + ["198", "51", "100", "120"].join(".");

describe.each([false, true])("an IPv4-mapped address before a phone number (maskPublicIps=%s)", (mask) => {
  it("splits the phone number: the address keeps its token, the rest of the number is its own", () => {
    const input = `x ${MAPPED} ${PHONE_REST} y`;
    const r = run(input, mask);
    expect(r.out).toBe("x ANON_IP_1 ANON_PHONE_1 y");
    expect(r.values).toEqual([MAPPED, PHONE_REST]);
    expect(r.back).toBe(input);
  });

  it("saves the address as before and never the cut phone value", () => {
    const r = run(`x ${MAPPED} ${PHONE_REST} y`, mask);
    expect(r.saved).toContain(`IP:${MAPPED}`);
    expect(r.saved.filter((s) => s.startsWith("PHONE:"))).toEqual([]);
  });

  it("reads an upper-case prefix the same way", () => {
    const input = `x ::FFFF:10.0.0.100 ${PHONE_REST} y`;
    expect(run(input, mask).out).toBe("x ANON_IP_1 ANON_PHONE_1 y");
  });

  it("leaves the address alone with the phone category off", () => {
    expect(run(`x ${MAPPED} ${PHONE_REST} y`, mask, false).out).toBe(`x ANON_IP_1 ${PHONE_REST} y`);
  });

  it("does not split a port number or a one-digit last number", () => {
    expect(run(`x ${MAPPED} 443 y`, mask).out).toBe("x ANON_IP_1 443 y");
    expect(run(`x ::ffff:10.0.0.5 ${PHONE_REST} y`, mask).out).toBe(`x ANON_IP_1 ${PHONE_REST} y`);
  });

  it("keeps the address token alone when the rest of the number is suppressed", () => {
    const r = run(`x ${MAPPED} ${PHONE_REST} y`, mask, true, [PHONE_REST]);
    expect(r.out).toBe(`x ANON_IP_1 ${PHONE_REST} y`);
  });
});

describe("a public IPv4-mapped address before a phone number", () => {
  it("splits the phone number with public masking on", () => {
    const input = `x ${PUBLIC_MAPPED} ${PHONE_REST} y`;
    const r = run(input, true);
    expect(r.out).toBe("x ANON_EXTIP_1 ANON_PHONE_1 y");
    expect(r.back).toBe(input);
  });

  it("leaves the address in clear with public masking off, and the phone pass reads the number", () => {
    const input = `x ${PUBLIC_MAPPED} ${PHONE_REST} y`;
    const r = run(input, false);
    expect(r.out).toBe(`x ${PUBLIC_MAPPED.slice(0, -3)}ANON_PHONE_1 y`);
    expect(r.back).toBe(input);
  });
});

describe("a phone number that starts before the last number of an IPv4-mapped address", () => {
  it("is split as after an address whose dotted tail is cut (2001:db8::)", () => {
    for (const prefix of ["::ffff:", "2001:db8::"]) {
      const input = `x ${prefix}${["198", "51", "100", "120"].join(".")} 4624 y`;
      const r = run(input, true);
      expect(r.out).toBe("x ANON_EXTIP_1 ANON_PHONE_1 y");
      expect(r.back).toBe(input);
    }
  });
});

describe("a seeded call with a saved IPv4-mapped address", () => {
  it("masks as much as a call without saved values", () => {
    const input = `x ${MAPPED} ${PHONE_REST} y`;
    for (const mask of [false, true]) {
      const first = createAnonymizer(policy(mask), known());
      first.apply(input);
      const seeded = createAnonymizer(policy(mask), { ...known(), custom: first.discoveries() });
      const out = seeded.apply(input);
      expect(out).toBe("x ANON_IP_1 ANON_PHONE_1 y");
      expect(seeded.restore(out)).toBe(input);
    }
  });
});
