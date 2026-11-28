import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type AnonTokenCategory,
  type CustomEntity,
} from "../../src/analysis/anonymize.js";

// #2995: the dotted IPv4 tail after an IPv6 address that #2990 left in clear. The tail joins the
// token LATE, after every text pass, and only while it is still intact. Synthetic values only:
// fd00::/16, 2001:db8::/32, 555-01xx and the .invalid TLD.

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
const run = (text: string, mask: boolean, o: Opts = {}) => {
  const a = make(mask, o);
  const out = a.apply(text);
  return { a, out, back: a.restore(out), values: a.pairs().map((p) => p.value) };
};
// The octets that must never reach the wire in clear, checked on the masked text.
const noOctets = (out: string, ...octets: string[]) => {
  for (const o of octets) expect(out).not.toContain(o);
};
const RANGE: CustomEntity[] = [{ value: "fd00::/16", category: "IP", match: "pattern" }];
const MAIL = ["mail", "invalid"].join(".");
// Assembled at runtime so no phone- or profile-path-shaped literal sits in the repo.
const NUM = ["555", "0100"].join("-");
const LONG = `100 ${NUM}`;
const phoneToken = (n: number) => ["ANON", "PHONE", String(n)].join("_");
const PROFILE = ["C:", "Users", ""].join("\\");

describe.each([true, false])(
  "phone category on: the whole address and the rest of the number (#2995), mask=%s",
  (mask) => {
    const PHONE = { PHONE: true };

    it("masks the whole IPv6+IPv4 address as one IP token and the rest of the phone number as a PHONE token", () => {
      const input = `fd00::192.168.1.100 ${NUM}`;
      const r = run(input, mask, { cats: PHONE });
      expect(r.out).toBe("ANON_IP_1 ANON_PHONE_1");
      expect(r.a.pairs()).toEqual([
        { token: "ANON_IP_1", value: "fd00::192.168.1.100", category: "IP" },
        // Never in the text: the pairs the head and the number had before, so both stay saved as before.
        { token: "ANON_IP_2", value: "fd00::192", category: "IP" },
        { token: phoneToken(1), value: NUM, category: "PHONE" },
        { token: phoneToken(2), value: LONG, category: "PHONE" },
      ]);
      expect(r.back).toBe(input);
    });

    it("saves what it saved before and never the cut phone number, so a later call masks the whole number", () => {
      const first = make(mask, { cats: PHONE });
      first.apply(`fd00::192.168.1.100 ${NUM}`);
      const disc = first.discoveries();
      expect(disc.map((x) => x.value).sort()).toEqual([LONG, "fd00::192"]);
      const later = run(`call 100 ${NUM} now`, mask, { cats: PHONE, custom: disc });
      expect(later.out).toBe("call ANON_PHONE_1 now");
      expect(later.values).toEqual([LONG]);
    });

    it("a later call never uncovers a fifth octet through a saved value", () => {
      const first = make(mask, { cats: PHONE });
      first.apply(`fd00::192.168.1.100 ${NUM}`);
      const input = "x fd00::192.168.1.100.5 y fd00::192.168.1.10 z";
      const r = run(input, mask, { cats: PHONE, custom: first.discoveries() });
      expect(r.out).toBe(run(input, mask, { cats: PHONE }).out);
      expect(r.back).toBe(input);
    });

    it("keeps today's output when the rest of the phone number is suppressed", () => {
      const r = run(`fd00::192.168.1.100 ${NUM}`, mask, { cats: PHONE, suppressed: [NUM] });
      expect(r.out).toBe("ANON_IP_1.168.1.ANON_PHONE_1");
    });

    it("does the same through a custom range with the IP category off", () => {
      const input = `Evtx::fd00::10.0.0.100 ${NUM}`;
      const r = run(input, mask, { cats: { ...PHONE, IP: false }, custom: RANGE });
      noOctets(r.out, ".0.0.", "555");
      expect(r.out).toMatch(/^Evtx::ANON_IP_\d+ ANON_PHONE_\d+$/);
      expect(r.back).toBe(input);
    });

    it("does the same for a custom group that ends in the address head", () => {
      const input = `x lab-fd00::10.0.0.100 ${NUM}`;
      const r = run(input, mask, { cats: PHONE, custom: [{ value: "lab-fd00::10", category: "HOST" }] });
      noOctets(r.out, ".0.0.", "555");
      expect(r.back).toBe(input);
    });
  },
);

describe.each([true, false])("IP category off with a custom IPv6 range (#2995 case 2), mask=%s", (mask) => {
  it.each([
    ["Evtx::fd00::10.0.0.5", "Evtx::"],
    ["node12:fd00::10.0.0.5", "node12:"],
    ["x fd00::10.0.0.5:443 y", "x "],
  ])("%s masks the whole address", (input, lead) => {
    const r = run(input, mask, { cats: { IP: false }, custom: RANGE });
    noOctets(r.out, ".0.0.5");
    expect(r.out.startsWith(lead)).toBe(true);
    expect(r.values).toContain("fd00::10.0.0.5");
    expect(r.back).toBe(input);
  });

  it("leaves a tail an earlier pass took to that pass (an email domain stays masked)", () => {
    const input = `Evtx::fd00::10.0.0.5@${MAIL}`;
    const r = run(input, mask, { cats: { IP: false, EMAIL: true }, custom: RANGE });
    expect(r.out).not.toContain(MAIL);
    expect(r.back).toBe(input);
  });

  it("leaves a fifth octet as today", () => {
    const r = run("Evtx::fd00::10.0.0.5.7", mask, { cats: { IP: false }, custom: RANGE });
    expect(r.out).toBe("Evtx::ANON_IP_1.0.0.5.7");
  });

  it("saves the head, as before, and not the joined value", () => {
    const first = make(mask, { cats: { IP: false }, custom: RANGE });
    first.apply("Evtx::fd00::10.0.0.5");
    expect(first.discoveries().map((x) => x.value)).toEqual(["fd00::10"]);
    const input = "x fd00::10.0.0.5.7 y";
    expect(run(input, mask, { custom: first.discoveries() }).out).toBe(run(input, mask).out);
  });

  it("a second call seeded with the first call's discoveries masks the whole address too", () => {
    const first = make(mask, { cats: { IP: false }, custom: RANGE });
    first.apply("Evtx::fd00::10.0.0.5");
    const r = run("node12:fd00::10.0.0.5 x fd00::10.0.0.5 y", mask, {
      cats: { IP: false },
      custom: [...RANGE, ...first.discoveries()],
    });
    noOctets(r.out, ".0.0.5");
    expect(r.back).toBe("node12:fd00::10.0.0.5 x fd00::10.0.0.5 y");
  });
});

describe.each([true, false])("custom value that ends in the address head (#2995 case 3), mask=%s", (mask) => {
  it.each([
    ["x lab-fd00::10.0.0.5 y", "lab-fd00::10"],
    ["x srv01:fd00::10.0.0.5 y", "srv01:fd00::10"],
    ["x fd00::10.0.0.5 y", "x fd00"],
  ])("%s with custom %s", (input, value) => {
    const r = run(input, mask, { custom: [{ value, category: "HOST" }] });
    noOctets(r.out, ".0.0.5");
    expect(r.out).toMatch(/ANON_HOST_\d+/);
    expect(r.back).toBe(input);
  });

  it("keeps an email after the tail masked", () => {
    const input = `x lab-fd00::10.0.0.5@${MAIL}`;
    const r = run(input, mask, {
      cats: { EMAIL: true },
      custom: [{ value: "lab-fd00::10", category: "HOST" }],
    });
    expect(r.out).not.toContain(MAIL);
    expect(r.back).toBe(input);
  });
});

describe.each([true, false])(
  "an IPv4 address glued right after a complete IPv6 address (#2995), mask=%s",
  (mask) => {
    it.each([
      "x fd00::ab:12cd192.168.1.5 y",
      "x fd00::1fd0192.168.1.5 y",
      `${PROFILE}fd00::ab:12cd192.168.1.5`,
      `${PROFILE}\u00B7\u00B70fd00::ab:12cd192.168.1.5`,
      "x fd00::ab:12cd\u00B7192.168.1.5 y",
    ])("%s masks the IPv4", (input) => {
      const r = run(input, mask, { cats: { PATH: true } });
      noOctets(r.out, "192.168", "168.1.5");
      expect(r.values).toContain("192.168.1.5");
      expect(r.back).toBe(input);
    });

    it("masks it after a public address kept visible", () => {
      const input = "x 2001:db8::abcd10.0.0.5 y";
      const r = run(input, mask);
      noOctets(r.out, "10.0.0.5");
      expect(r.back).toBe(input);
    });

    it("masks it after an address the analyst suppressed", () => {
      const input = "x fd00::ab:12cd10.0.0.5 y";
      const r = run(input, mask, { suppressed: ["fd00::ab:12cd"] });
      expect(r.out).toBe("x fd00::ab:12cdANON_IP_1 y");
      expect(r.back).toBe(input);
    });

    it("masks it after a custom group set aside with the address", () => {
      const input = "x lab-fd00::ab:12cd192.168.1.5 y";
      const r = run(input, mask, { custom: [{ value: "lab-fd00", category: "HOST" }] });
      noOctets(r.out, "192.168", "168.1.5");
      expect(r.back).toBe(input);
    });

    it("splits a phone number that starts in its last octet, as for a dotted tail", () => {
      const input = `x fd00::ab:12cd192.168.1.100 ${NUM}`;
      const r = run(input, mask, { cats: { PHONE: true } });
      noOctets(r.out, "168", "555");
      expect(r.back).toBe(input);
    });

    it("keeps a public IPv4 visible with public masking off, readable after the token", () => {
      const pub = [8, 8, 4, 4].join(".");
      const input = `x fd00::ab:12cd${pub} y`;
      const r = run(input, mask);
      expect(r.back).toBe(input);
      if (!mask) expect(r.out).toContain(pub);
      else noOctets(r.out, pub);
    });
  },
);
