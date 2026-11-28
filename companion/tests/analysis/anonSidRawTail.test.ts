import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3048: three shapes the #3037/#3043 fixes did not reach.
// 1. REG category off, IP on: an IPv4 address glued after a SID went to the AI whole in clear.
// 2. A RID plus the address's first number longer than 10 digits: the SID pattern did not match,
//    so the SID and the address both went in clear.
// 3. An IPv6 address with an all-digit last group, then a dotted phone number: the phone part
//    after the address went in clear.
// Synthetic values only; the addresses are built at runtime.

function policy(mask: boolean, REG: boolean, IP = true): AnonPolicy {
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

type Opts = { REG?: boolean; IP?: boolean; seed?: string; seedREG?: boolean };
function run(input: string, mask: boolean, opts: Opts = {}) {
  const REG = opts.REG ?? true;
  let custom: KnownEntities["custom"] = [];
  if (opts.seed !== undefined) {
    const first = createAnonymizer(policy(mask, opts.seedREG ?? REG), known());
    first.apply(opts.seed);
    custom = first.discoveries();
  }
  const a = createAnonymizer(policy(mask, REG, opts.IP ?? true), known(custom));
  const out = a.apply(input);
  const tokens = out.match(/ANON_[A-Z]+_\d+/g) ?? [];
  return {
    out,
    values: tokens.map((t) => a.restore(t)),
    back: a.restore(out),
    saved: a.discoveries().map((e) => `${e.category}:${e.value}`),
  };
}

const PREFIX = "S-1-5-21-1111111111-2222222222-3333333333-";
const ip = (...n: number[]) => n.join(".");
const PRIVATE = ip(192, 168, 1, 5);

describe.each([false, true])(
  "REG off, IP on: a SID with an IPv4 glued after it (maskPublicIps=%s)",
  (mask) => {
    const off = { REG: false };

    it("masks the RID digits and the address in one IP token; the SID prefix stays as REG off leaves it", () => {
      const input = `x ${PREFIX}1001${PRIVATE} y`;
      const r = run(input, mask, off);
      expect(r.out).toMatch(new RegExp(`^x ${PREFIX}ANON_IP_\\d+ y$`));
      expect(r.values).toEqual([`1001${PRIVATE}`]);
      expect(r.back).toBe(input);
    });

    it("never saves the joined value", () => {
      const r = run(`x ${PREFIX}1001${PRIVATE} y`, mask, off);
      expect(r.saved).toEqual([]);
    });

    it("joins a fifth number and splits a phone number that starts in the last one", () => {
      const five = `x ${PREFIX}1001${PRIVATE}.6 y`;
      const r5 = run(five, mask, off);
      expect(r5.out).toMatch(new RegExp(`^x ${PREFIX}ANON_[A-Z]+_\\d+ y$`));
      expect(r5.back).toBe(five);
      const phone = `x ${PREFIX}1001${ip(192, 168, 1, 100)} 555-0100 y`;
      const rp = run(phone, mask, off);
      expect(rp.out).toMatch(new RegExp(`^x ${PREFIX}ANON_IP_\\d+ ANON_PHONE_\\d+ y$`));
      expect(rp.back).toBe(phone);
    });

    it("masks it the same on a call seeded with the first call's saved values", () => {
      for (const input of [`x ${PREFIX}1001${PRIVATE} y`, `x ${PREFIX}1001${PRIVATE}.6 y`]) {
        const r = run(input, mask, { ...off, seed: input });
        expect(r.out).toMatch(new RegExp(`^x ${PREFIX}ANON_[A-Z]+_\\d+ y$`));
        expect(r.back).toBe(input);
      }
    });

    it("leaves a public reading in clear with public masking off, as the IPv4 pass does", () => {
      const input = `x ${PREFIX}1001${ip(8, 8, 8, 8)} y`;
      const r = run(input, mask, off);
      if (mask) expect(r.out).toMatch(new RegExp(`^x ${PREFIX}ANON_EXTIP_\\d+ y$`));
      else expect(r.out).toBe(input);
      expect(r.back).toBe(input);
    });
  },
);

describe.each([false, true])("a RID plus first number longer than 10 digits (maskPublicIps=%s)", (mask) => {
  const SID10 = `${PREFIX}1234567890`;

  it("masks the SID and the address in one REG token", () => {
    for (const glued of [PRIVATE, ip(10, 0, 0, 5)]) {
      const input = `x ${SID10}${glued} y`;
      const r = run(input, mask);
      expect(r.out).toMatch(/^x ANON_REG_\d+ y$/);
      expect(r.values).toEqual([SID10 + glued]);
      expect(r.back).toBe(input);
    }
  });

  it("masks the SID with the IP category off", () => {
    const input = `x ${SID10}${PRIVATE} y`;
    const r = run(input, mask, { IP: false });
    // The address stays as the IP category off leaves it; the SID with its glued first number is masked.
    expect(r.out).toBe(`x ANON_REG_1.${PRIVATE.split(".").slice(1).join(".")} y`);
    expect(r.values).toEqual([`${SID10}192`]);
    expect(r.back).toBe(input);
  });

  it("masks the SID prefix's run with REG off too", () => {
    const input = `x ${SID10}${PRIVATE} y`;
    const r = run(input, mask, { REG: false });
    expect(r.out).toMatch(new RegExp(`^x ${PREFIX}ANON_IP_\\d+ y$`));
    expect(r.back).toBe(input);
  });

  it("masks it the same on a seeded call", () => {
    const input = `x ${SID10}${PRIVATE} y`;
    const r = run(input, mask, { seed: input });
    expect(r.out).toMatch(/^x ANON_REG_\d+ y$/);
    expect(r.back).toBe(input);
  });

  it("masks the SID when the saved values came from a call with REG off (a saved address or phone after it)", () => {
    const five = `x ${SID10}${ip(10, 10, 0, 0)}.5 y`;
    const phone = `x ${SID10}${ip(10, 0, 0, 100)} 555-0100 y`;
    const seeds = [`abc${ip(10, 10, 0, 0)}.5`, `x ${ip(10, 0, 0, 100)}.100 555-0100 y`];
    for (const [input, seed] of [
      [five, seeds[0]],
      [phone, seeds[1]],
    ])
      for (const IP of [true, false]) {
        const r = run(input, mask, { seed, seedREG: false, IP });
        expect(r.out.startsWith(`x ${PREFIX}`)).toBe(false);
        expect(r.out).toMatch(/^x ANON_REG_\d+/);
        expect(r.back).toBe(input);
      }
  });

  it("keeps a lone over-long last number as it was (no address after it)", () => {
    const input = `x ${PREFIX}12345678901 y`;
    expect(run(input, mask).out).toBe(input);
  });
});

describe.each([false, true])(
  "a dotted phone number after an all-digit last group (maskPublicIps=%s)",
  (mask) => {
    it("masks the address and the phone part as their own tokens", () => {
      for (const addr of ["fd00::164", "fd00::1:100"]) {
        const input = `x ${addr}.555.0100 y`;
        const r = run(input, mask);
        expect(r.out).toMatch(/^x ANON_IP_\d+\.ANON_PHONE_\d+ y$/);
        expect(r.values).toEqual([addr, "555.0100"]);
        expect(r.back).toBe(input);
      }
    });

    it("masks it the same on a seeded call, and never saves the phone part", () => {
      const input = "x fd00::164.555.0100 y";
      const r = run(input, mask, { seed: input });
      expect(r.out).toMatch(/^x ANON_IP_\d+\.ANON_PHONE_\d+ y$/);
      expect(r.back).toBe(input);
      expect(r.saved).not.toContain("PHONE:555.0100");
    });

    it("leaves no number after a public address in clear", () => {
      const input = "x 2001:db8::164.555.0100 y";
      const r = run(input, mask);
      expect(r.out).not.toMatch(/555|0100/);
      expect(r.back).toBe(input);
    });
  },
);
