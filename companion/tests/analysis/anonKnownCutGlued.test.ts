import { describe, expect, it } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";
import { extractAccounts, learnableAccounts } from "../../src/analysis/assetGraph.js";

// #3058 — a saved short value no longer cuts a known domain, a composite value keeps the input's
// spelling, glued IPv4 and card shapes get their own tokens, and the account readers outside
// anonUsernames.ts read DOMAIN\user the #3049 way. Addresses, domains and cards are built at runtime.

function policy(maskPublicIps = true, over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: {
      ...{ IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true },
      ...{ CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
      ...over,
    },
  };
}
const DOMAIN = ["corp", "local"].join(".");
const known = (over: Partial<KnownEntities> = {}): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [DOMAIN],
  usernames: [],
  suppressed: [],
  ...over,
});
const ip = (...parts: Array<number | string>) => parts.join(".");
const CARD = ["4111", "1111", "1111", "1111"];

describe("a saved or custom value inside a known domain (#3058)", () => {
  it("a qualifier saved from DOMAIN\\user does not cut the domain on a later call", () => {
    const first = createAnonymizer(policy(), known());
    first.apply("logon corp\\bob ok");
    const later = createAnonymizer(policy(), known({ custom: first.discoveries() }));
    for (const text of [`host ${DOMAIN} ok`, `x.${DOMAIN} ok`, `bob@${DOMAIN} ok`]) {
      const out = later.apply(text);
      expect(out).not.toMatch(/corp|local/i);
      expect(later.restore(out)).toBe(text);
    }
  });

  it("an analyst custom value grows to the whole known domain", () => {
    const a = createAnonymizer(policy(), known({ custom: [{ category: "DOMAIN", value: "corp" }] }));
    const out = a.apply(`host srv.${DOMAIN} ok`);
    expect(out).not.toContain("local");
    expect(a.restore(out)).toBe(`host srv.${DOMAIN} ok`);
  });

  it("a suppressed known domain grows nothing: the custom value is replaced as before", () => {
    const custom = [{ category: "DOMAIN" as const, value: "corp" }];
    const a = createAnonymizer(policy(), known({ custom, suppressed: [DOMAIN] }));
    expect(a.apply(`host ${DOMAIN} ok`)).toBe("host ANON_DOMAIN_1.local ok");
  });
});

describe("a composite value keeps the input's spelling (#3058)", () => {
  it("an account around a case-insensitive custom match restores as written", () => {
    const a = createAnonymizer(policy(), known({ custom: [{ category: "DOMAIN", value: "CORP" }] }));
    const text = "logon CORP\\5, LAB\\jdoe-corp";
    const out = a.apply(text);
    expect(out).not.toMatch(/corp|jdoe/i);
    expect(a.restore(out)).toBe(text);
  });

  it("one token per value still restores one spelling (by design)", () => {
    const a = createAnonymizer(policy(), known({ custom: [{ category: "DOMAIN", value: "CORP" }] }));
    expect(a.restore(a.apply("CORP x corp"))).toBe("CORP x CORP");
  });
});

describe("glued IPv4 and card shapes (#3058)", () => {
  it("an internal address with digits glued on, or a last part over 255, is masked whole", () => {
    const a = createAnonymizer(policy(), known());
    for (const v of [ip(10, 0, 0, "123456789"), ip(10, 0, 0, 512), ip(192, 168, 1, 1234)]) {
      const out = a.apply(`ran ${v} x`);
      expect(out).toMatch(/^ran ANON_IP_\d+ x$/);
      expect(a.restore(out)).toBe(`ran ${v} x`);
    }
  });

  it("a public head with digits glued on is masked, and stays clear with public masking off", () => {
    const on = createAnonymizer(policy(true), known());
    const version = ip(2, 0, 0, 1024); // #3062: a short last part is masked too, under public masking
    expect(on.apply(`v ${version}`)).toMatch(/^v ANON_EXTIP_\d+$/);
    expect(createAnonymizer(policy(false), known()).apply(`v ${version}`)).toBe(`v ${version}`);
    expect(on.apply(`ran ${ip(8, 8, 8, "823456789")} y`)).toMatch(/^ran ANON_EXTIP_\d+ y$/);
    const off = createAnonymizer(policy(false), known());
    expect(off.apply(`ran ${ip(8, 8, 8, "823456789")} y`)).toBe(`ran ${ip(8, 8, 8, "823456789")} y`);
  });

  it("a grouped card with a digit glued on either end is masked whole", () => {
    const a = createAnonymizer(policy(), known());
    for (const v of [`${CARD.join(" ")}5`, `5${CARD.join(" ")}`, `12${CARD.join("-")}3`]) {
      const out = a.apply(`card ${v} x`);
      expect(out).toMatch(/^card ANON_CARD_\d+ x$/);
      expect(a.restore(out)).toBe(`card ${v} x`);
    }
  });

  it("a bare digit run with a digit glued on is not read as a card", () => {
    const a = createAnonymizer(policy(), known());
    const run = `${CARD.join("")}5`;
    expect(a.apply(`n ${run}`)).toBe(`n ${run}`);
  });
});

describe("account readers outside anonUsernames.ts (#3058)", () => {
  it("extractAccounts reads a long user half and a non-ASCII qualifier whole", () => {
    const long = "averyveryverylongusername01";
    expect(extractAccounts(`logon CORP\\${long} ok`)).toEqual([`CORP\\${long}`]);
    expect(extractAccounts("logon Øyvind\\bob ok")).toEqual(["Øyvind\\bob"]);
    expect(extractAccounts("logon CORP\\kåre ran")).toEqual(["CORP\\kåre"]);
  });

  it("learnableAccounts keeps the readings of the old pattern", () => {
    const text = "logon Øyvind\\bob, CORP\\bobélan-x ok";
    const got = learnableAccounts(text);
    expect(got).toEqual(expect.arrayContaining(extractAccounts(text)));
    expect(got).toEqual(expect.arrayContaining(["yvind\\bob", "CORP\\bob"]));
  });

  it("a secret glued after a non-ASCII qualifier takes the whole qualifier with it", () => {
    const key = ["sk", "live", "ABCDEFGHIJKLMNOPQRSTUVWX"].join("_");
    const out = createAnonymizer(policy(), known()).apply(`logon Øyvind\\${key} ok`);
    expect(out).not.toContain("yvind");
    expect(out).not.toContain("Ø");
  });
});
