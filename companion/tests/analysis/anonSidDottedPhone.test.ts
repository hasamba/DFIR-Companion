import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3065: a Windows SID, a private IPv4 address glued directly after it whose last number has three
// digits, then a dotted phone number. Call 1 saves the SID with the address's first number attached
// and the phone number from the address's last number on. On a seeded call both saved values were
// masked, and the address's middle numbers between them went to the AI in clear. A fresh call
// masks it all. Synthetic values only.

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

type Opts = { REG?: boolean; seedREG?: boolean; seedIP?: boolean; seed?: boolean };
function run(input: string, mask: boolean, opts: Opts = {}) {
  let custom: KnownEntities["custom"] = [];
  if (opts.seed ?? true) {
    const first = createAnonymizer(policy(mask, opts.seedREG ?? true, opts.seedIP ?? true), known());
    first.apply(input);
    custom = first.discoveries();
  }
  const a = createAnonymizer(policy(mask, opts.REG ?? true), known(custom));
  const out = a.apply(input);
  return {
    out,
    back: a.restore(out),
    saved: a.discoveries().map((e) => `${e.category}:${e.value}`),
  };
}

const SID = "S-1-5-21-1111111111-2222222222-3333333333-";
const addr = (...n: number[]) => n.join(".");
const PHONE = ".555.0100";
const ADDRS = [addr(10, 0, 0, 100), addr(192, 168, 1, 100), addr(172, 16, 5, 250)];
const RIDS = ["1001", "1234567890"];

describe("seeded SID + IPv4 + dotted phone (#3065)", () => {
  for (const mask of [false, true])
    for (const rid of RIDS)
      for (const ip of ADDRS) {
        const input = `x ${SID}${rid}${ip}${PHONE} y`;
        it(`masks the whole run on a seeded call (rid ${rid.length}, ${ip.split(".")[0]}.x, mask ${mask})`, () => {
          const r = run(input, mask);
          expect(r.out).toMatch(/^x ANON_REG_\d+\.ANON_PHONE_\d+ y$/);
          expect(r.back).toBe(input);
        });
      }

  it("masks no less than a fresh call, whatever call 1 had on", () => {
    const input = `x ${SID}1001${ADDRS[0]}${PHONE} y`;
    for (const mask of [false, true])
      for (const seedREG of [true, false])
        for (const seedIP of [true, false])
          for (const REG of [true, false]) {
            const fresh = run(input, mask, { REG, seed: false }).out;
            const seeded = run(input, mask, { REG, seedREG, seedIP });
            const clear = (s: string) => s.replace(/ANON_[A-Z]+_\d+/g, "").replace(/[^0-9]/g, "");
            expect(clear(seeded.out).length).toBeLessThanOrEqual(clear(fresh).length);
            expect(seeded.out).not.toContain(".0.0.");
            expect(seeded.back).toBe(input);
          }
  });

  it("with REG off on the seeded call, the SID's saved value still masks the run", () => {
    const input = `x ${SID}1001${ADDRS[0]}${PHONE} y`;
    const r = run(input, false, { REG: false });
    expect(r.out).not.toContain(".0.0.");
    expect(r.back).toBe(input);
  });

  it("does not save the joined run or the split phone rest as new values", () => {
    const input = `x ${SID}1001${ADDRS[0]}${PHONE} y`;
    const first = createAnonymizer(policy(false, true), known());
    first.apply(input);
    const seeded = run(input, false);
    expect([...seeded.saved].sort()).toEqual(
      first
        .discoveries()
        .map((e) => `${e.category}:${e.value}`)
        .sort(),
    );
  });

  it("leaves a spaced phone after the address as before", () => {
    const input = `x ${SID}1001${ADDRS[0]} 555-0100 y`;
    const r = run(input, false);
    expect(r.out).toMatch(/^x ANON_REG_\d+ ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
  });
});
