import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3037: a Windows SID with an IPv4 address glued right after it. The RID group of the SID pattern
// takes the address's first number, and the rest of the address (".168.1.5") went to the AI in
// clear. Where the RID ends cannot be known, so the dotted numbers join the SID token, never saved.
// Synthetic values only; the addresses are built at runtime.

function policy(maskPublicIps: boolean, IP = true, PHONE = true): AnonPolicy {
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
      REG: true,
      CARD: false,
      PHONE,
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

const SID = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const ip = (...n: number[]) => n.join(".");
const PRIVATE = ip(192, 168, 1, 5);
const PUBLIC = ip(8, 8, 8, 8);

describe.each([false, true])("an IPv4 address glued after a SID (maskPublicIps=%s)", (mask) => {
  it("masks the SID and the whole address in one token, no number in clear", () => {
    const input = `x ${SID}${PRIVATE} y`;
    const r = run(input, mask);
    expect(r.out).toMatch(/^x ANON_REG_\d+ y$/);
    expect(r.values).toEqual([SID + PRIVATE]);
    expect(r.back).toBe(input);
  });

  it("never saves the joined value; the SID as the SID pass read it stays saved", () => {
    const r = run(`x ${SID}${PRIVATE} y`, mask);
    expect(r.saved).toEqual([`REG:${SID}192`]);
  });

  it("joins a first number of any length and a fifth number", () => {
    for (const glued of [ip(10, 0, 0, 5), PRIVATE + ".6"]) {
      const input = `x ${SID}${glued} y`;
      const r = run(input, mask);
      expect(r.out).toMatch(/^x ANON_REG_\d+ y$/);
      expect(r.back).toBe(input);
    }
  });

  it("splits a phone number that starts in the address's last number", () => {
    const input = `x ${SID}${ip(192, 168, 1, 100)} 555-0100 y`;
    const r = run(input, mask);
    expect(r.out).toMatch(/^x ANON_REG_\d+ ANON_PHONE_\d+ y$/);
    expect(r.values).toEqual([SID + ip(192, 168, 1, 100), "555-0100"]);
    expect(r.back).toBe(input);
    expect(r.saved).toContain("PHONE:100 555-0100"); // the number as the phone pass read it, as before
    expect(r.saved).not.toContain("PHONE:555-0100");
  });

  it("saves no phone value when the run holds a whole address the phone number starts in", () => {
    const input = `x ${SID}${ip(10, 10, 0, 0, 100)} 555-0100 y`;
    const r = run(input, mask);
    expect(r.out).toMatch(/^x ANON_REG_\d+ ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
    expect(r.saved).toContain(`IP:${ip(10, 0, 0, 100)}`); // the address the IPv4 pass reads, as before
    expect(r.saved.filter((v) => v.startsWith("PHONE:"))).toEqual([]);
  });

  it("does the same on a call seeded with the values a first call saved", () => {
    for (const input of [`x ${SID}${PRIVATE} y`, `x ${SID}${ip(192, 168, 1, 100)} 555-0100 y`]) {
      const first = run(input, mask);
      const r = run(input, mask, { custom: first.discoveries });
      expect(r.out).not.toMatch(/\d\.\d/);
      expect(r.out).not.toMatch(/ \d/);
      expect(r.back).toBe(input);
    }
  });

  it("joins a run that ends in a saved phone value, and still mints the address in it", () => {
    const run5 = ip(192, 168, 1, 5, 100);
    const first = run(`x ${run5} 555-0100 y`, mask);
    const input = `x ${SID}${run5} 555-0100 y`;
    const r = run(input, mask, { custom: first.discoveries });
    expect(r.out).toMatch(/^x ANON_REG_\d+ ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
    if (mask) expect(r.saved).toContain(`EXTIP:${ip(168, 1, 5, 100)}`);
  });

  it("leaves a SID with a space before the address as two tokens", () => {
    const input = `x ${SID} ${PRIVATE} y`;
    const r = run(input, mask);
    expect(r.values).toEqual([SID, PRIVATE]);
  });

  it("changes nothing with the IP category off", () => {
    const input = `x ${SID}${PRIVATE} y`;
    expect(run(input, mask, { IP: false }).out).toBe(`x ANON_REG_1.${ip(168, 1, 5)} y`);
  });
});

describe("a public address glued after a SID", () => {
  it("is joined with public masking on", () => {
    const r = run(`x ${SID}${PUBLIC} y`, true);
    expect(r.out).toMatch(/^x ANON_REG_\d+ y$/);
  });

  it("keeps today's output with public masking off: no reading is an address the IPv4 pass masks", () => {
    expect(run(`x ${SID}${PUBLIC} y`, false).out).toBe(`x ANON_REG_1.${ip(8, 8, 8)} y`);
  });
});
