import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3043: a phone number after an address still went to the AI in clear in three shapes: an IPv6
// address whose last group is all digits ("fd00::164 555-0100"), and two seeded calls whose saved
// address ends in a dotted IPv4 that a phone number starts in after its first number. The number is
// its own PHONE token, never saved. Synthetic values only; public addresses are built at runtime.

function policy(maskPublicIps: boolean, IP = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
    categories: {
      IP,
      EMAIL: false,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
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

function run(input: string, mask: boolean, opts: { IP?: boolean; custom?: KnownEntities["custom"] } = {}) {
  const a = createAnonymizer(policy(mask, opts.IP ?? true), known(opts.custom));
  const out = a.apply(input);
  const tokens = out.match(/ANON_[A-Z]+_\d+/g) ?? [];
  return {
    out,
    values: tokens.map((t) => a.restore(t)),
    back: a.restore(out),
    saved: a.discoveries().map((e) => `${e.category}:${e.value}`),
    discoveries: a.discoveries(),
  };
}

const REST = "555-0100";
const DOC_V4 = ["198", "51", "100", "120"].join(".");
const PUBLIC_MAPPED = "::ffff:" + DOC_V4;
const PUBLIC_DOTTED = "2001:db8::" + DOC_V4;

describe.each([false, true])("a phone number after a last group of digits (maskPublicIps=%s)", (mask) => {
  for (const addr of ["fd00::164", "fd00::1:100"]) {
    it(`splits it after ${addr}: the address keeps its token, the rest of the number is its own`, () => {
      const input = `x ${addr} ${REST} y`;
      const r = run(input, mask);
      expect(r.out).toBe("x ANON_IP_1 ANON_PHONE_1 y");
      expect(r.values).toEqual([addr, REST]);
      expect(r.back).toBe(input);
      expect(r.saved).toEqual([`IP:${addr}`]); // the cut phone value is never saved
    });
  }

  it("does the same on a call seeded with the saved address", () => {
    const input = `x fd00::164 ${REST} y`;
    const first = run("x fd00::164 y", mask);
    for (const IP of [true, false]) {
      const r = run(input, mask, { IP, custom: first.discoveries });
      expect(r.out).toBe("x ANON_IP_1 ANON_PHONE_1 y");
      expect(r.back).toBe(input);
      expect(r.saved).not.toContain(`PHONE:${REST}`);
    }
  });

  it("splits an Israeli number that starts in the last group", () => {
    const input = "x fd00::052-1234567 y";
    const r = run(input, mask);
    expect(r.out).toBe("x ANON_IP_1-ANON_PHONE_1 y");
    expect(r.back).toBe(input);
  });

  it("leaves a group that starts no phone number as it was", () => {
    expect(run("x fd00::164 4624 y", mask).out).toBe("x ANON_IP_1 4624 y");
    expect(run(`x fd00::164.${REST} y`, mask).out).toBe(`x ANON_IP_1.${REST} y`);
  });
});

describe("a public address with a last group of digits, public masking on", () => {
  it("splits the phone number after it", () => {
    const addr = "2001:db8::1:100";
    const r = run(`x ${addr} ${REST} y`, true);
    expect(r.out).toBe("x ANON_EXTIP_1 ANON_PHONE_1 y");
    expect(r.values).toEqual([addr, REST]);
  });

  it("keeps the phone pass's reading with public masking off", () => {
    expect(run(`x 2001:db8::1:100 ${REST} y`, false).out).toBe("x 2001:db8::1:ANON_PHONE_1 y");
  });
});

describe("a seeded call whose saved address ends in a dotted IPv4, then a number", () => {
  it("masks the number as its own token with the IP category off (saved IPv4-mapped address)", () => {
    const first = run(`x ${PUBLIC_MAPPED} y`, true);
    const input = `x ${PUBLIC_MAPPED} 4624 y`;
    const r = run(input, true, { IP: false, custom: first.discoveries });
    expect(r.out).toBe("x ANON_EXTIP_1 ANON_PHONE_1 y");
    expect(r.values).toEqual([PUBLIC_MAPPED, "4624"]);
    expect(r.back).toBe(input);
    expect(r.saved).not.toContain("PHONE:4624");
  });

  it("masks the number as its own token with public masking on (saved 2001:db8:: + IPv4)", () => {
    const first = run(`x ${PUBLIC_DOTTED} y`, true);
    const input = `x ${PUBLIC_DOTTED} 4624 y`;
    const r = run(input, true, { custom: first.discoveries });
    expect(r.out).toBe("x ANON_EXTIP_1 ANON_PHONE_1 y");
    expect(r.values).toEqual([PUBLIC_DOTTED, "4624"]);
    expect(r.back).toBe(input);
    expect(r.saved).not.toContain("PHONE:4624");
  });
});
