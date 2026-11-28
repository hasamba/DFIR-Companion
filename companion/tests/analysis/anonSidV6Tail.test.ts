import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3052: an IPv6 address glued directly after a Windows SID.
// 1. An address that opens with "::" (an IPv4-mapped or -compatible one, in hex) went to the AI
//    whole in clear, with the REG category on or off: the address scan read the RID's digits into
//    it ("1001::c0a8:105"), a literal it never masks, and no later pass reads IPv6.
// 2. With the REG category on, a SID glued to letters (an address the anonymizer does not mask, or
//    a plain word) went in clear: the SID pattern needed a word boundary after the RID.
// Synthetic values only.

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

type Opts = { REG?: boolean; IP?: boolean; seed?: string };
function run(input: string, mask: boolean, opts: Opts = {}) {
  const REG = opts.REG ?? true;
  let custom: KnownEntities["custom"] = [];
  if (opts.seed !== undefined) {
    const first = createAnonymizer(policy(mask, true), known());
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

const SID = "S-1-5-21-1111111111-2222222222-3333333333-1001";
// Hex spellings of private IPv4 addresses inside "::" forms.
const MAPPED = ["::ffff", "c0a8", "105"].join(":");
const COMPAT = ["", "", "c0a8", "105"].join(":");
const TEN = ["", "", "a00", "5"].join(":");

describe("#3052: a '::' IPv6 address glued after a SID", () => {
  for (const mask of [false, true]) {
    const m = mask ? "masking on" : "masking off";
    for (const addr of [MAPPED, COMPAT, TEN]) {
      it(`REG on: ${addr} after the REG token is its own IP token (${m})`, () => {
        const r = run(`x ${SID}${addr} y`, mask);
        expect(r.out).toMatch(/^x ANON_REG_\d+ANON_IP_\d+ y$/);
        expect(r.values).toEqual([SID, addr]);
        expect(r.back).toBe(`x ${SID}${addr} y`);
      });
      it(`REG off: ${addr} after a SID in clear is masked, the SID stays (${m})`, () => {
        const r = run(`x ${SID}${addr} y`, mask, { REG: false });
        expect(r.out).toMatch(new RegExp(`^x ${SID}ANON_IP_\\d+ y$`));
        expect(r.values).toEqual([addr]);
        expect(r.back).toBe(`x ${SID}${addr} y`);
      });
    }
    it(`a dotted mapped address keeps its saved IPv4 pair and is one token (${m})`, () => {
      const v4 = ["10", "0", "0", "5"].join(".");
      const r = run(`x ${SID}::ffff:${v4} y`, mask);
      expect(r.out).toMatch(/^x ANON_REG_\d+ANON_IP_\d+ y$/);
      expect(r.values).toEqual([SID, `::ffff:${v4}`]);
      expect(r.saved).toContain(`IP:${v4}`);
      expect(r.saved).not.toContain(`IP:::ffff:${v4}`);
    });
    it(`loopback ::1 after a SID is masked as when spaced (${m})`, () => {
      const r = run(`x ${SID}::1 y`, mask, { REG: false });
      expect(r.out).toMatch(new RegExp(`^x ${SID}ANON_IP_\\d+ y$`));
    });
    it(`a seeded call masks it the same way (${m})`, () => {
      const input = `x ${SID}${COMPAT} y`;
      for (const REG of [true, false]) {
        const r = run(input, mask, { REG, seed: input });
        expect(r.values).toContain(COMPAT);
        expect(r.back).toBe(input);
      }
    });
  }
  it("a seeded call whose saved IPv4 sits inside a mapped address joins it whole", () => {
    const v4 = ["10", "0", "0", "100"].join(".");
    const input = `x ${SID}::ffff:${v4} y`;
    const r = run(input, false, { seed: `x ${v4} y` });
    expect(r.out).toMatch(/^x ANON_REG_\d+ANON_IP_\d+ y$/);
    expect(r.values).toEqual([SID, `::ffff:${v4}`]);
    expect(r.back).toBe(input);
  });
  it("a saved value holding the address and a phone number is split in a seeded call", () => {
    const v4 = ["10", "0", "0", "100"].join(".");
    const input = `x ${SID}::ffff:${v4} 555-0100 y`;
    const r = run(input, false, { seed: `x ${SID}::ffff:${v4}.100 555-0100 y` });
    expect(r.out).toMatch(/^x ANON_REG_\d+ANON_IP_\d+ ANON_PHONE_\d+ y$/);
    expect(r.values).toEqual([SID, `::ffff:${v4}`, "555-0100"]);
    expect(r.back).toBe(input);
  });
  it("a public mapped address is masked only with public masking on", () => {
    const pub = ["::ffff", "808", "808"].join(":");
    expect(run(`x ${SID}${pub} y`, false, { REG: false }).out).toBe(`x ${SID}${pub} y`);
    expect(run(`x ${SID}${pub} y`, true, { REG: false }).out).toMatch(
      new RegExp(`^x ${SID}ANON_EXTIP_\\d+ y$`),
    );
  });
  it("a '::' word that is no address is left alone", () => {
    expect(run(`x ${SID}::abc y`, true, { REG: false }).out).toBe(`x ${SID}::abc y`);
  });
  it("the IP category off leaves the address in clear", () => {
    const r = run(`x ${SID}${COMPAT} y`, true, { IP: false });
    expect(r.out).toMatch(new RegExp(`^x ANON_REG_\\d+${COMPAT} y$`));
  });
  it("a fifth number after a dotted mapped address keeps today's reading", () => {
    const v4 = ["10", "0", "0", "5"].join(".");
    const r = run(`x ${SID}::ffff:${v4}.6 y`, true);
    expect(r.back).toBe(`x ${SID}::ffff:${v4}.6 y`);
    expect(r.values).not.toContain(`::ffff:${v4}`);
  });
});

describe("#3052: a SID glued to letters is still a REG token", () => {
  for (const tail of ["abc", "_x", "ff02::1", ["abcd", "ef01", "", "1"].join(":")]) {
    for (const IP of [true, false]) {
      it(`${tail} after the RID, IP ${IP ? "on" : "off"}`, () => {
        const r = run(`x ${SID}${tail} y`, true, { IP });
        expect(r.out.startsWith("x ANON_REG_")).toBe(true);
        expect(r.values[0]).toBe(SID);
        expect(r.back).toBe(`x ${SID}${tail} y`);
      });
    }
  }
  it("a private IPv6 glued after the SID with the IP category off: the SID is masked", () => {
    const r = run(`x ${SID}fd00::5 y`, true, { IP: false });
    expect(r.out).toBe("x ANON_REG_1fd00::5 y");
  });
  it("a 10-digit RID with a digit-led IPv6 glued on is still a REG token", () => {
    const long = "S-1-5-21-1111111111-2222222222-3333333333-1234567890";
    const addr = ["2001", "db8", "", "1", "100"].join(":");
    const r = run(`x ${long}${addr} y`, true, { IP: false });
    expect(r.out.startsWith("x ANON_REG_")).toBe(true);
    expect(r.back).toBe(`x ${long}${addr} y`);
  });
  it("a phone number that starts in the last group is split", () => {
    const r = run(`x ${SID}${COMPAT} 555-0100 y`, true, { REG: false });
    expect(r.out).toMatch(new RegExp(`^x ${SID}ANON_IP_\\d+ ANON_PHONE_\\d+ y$`));
  });
  it("a port after a dotted mapped address does not stop it", () => {
    const v4 = ["10", "0", "0", "5"].join(".");
    const r = run(`x ${SID}::ffff:${v4}:443 y`, true);
    expect(r.out).toMatch(/^x ANON_REG_\d+ANON_IP_\d+:443 y$/);
  });
  it("a longer number after the RID is still no SID", () => {
    const r = run(`x ${SID}23456789012 y`, true);
    expect(r.values).not.toContain(SID);
  });
});
