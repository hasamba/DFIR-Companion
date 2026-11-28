import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type CustomEntity,
} from "../../src/analysis/anonymize.js";

// #3006: a secret glued into an account or email name (an internal UPN, an external email, a
// DOMAIN\name, a custom value) became a reversible USER, EMAIL or custom token: restore() handed it
// back and the OCR path saved it as a discovery. Such a name now goes one way. The domain keeps its
// own token, and an external email goes whole, so its domain is never left in clear. Every
// secret-shaped value and address is assembled at runtime (like previewDiff.test.ts).
const join = (...parts: string[]) => parts.join("");
const AT = String.fromCharCode(0x40);
const BS = String.fromCharCode(0x5c);
const INTERNAL = ["contoso", "local"].join(".");
const EXTERNAL = ["gmail", "com"].join(".");
const SK = join("s", "k-", "Ab12Cd34Ef56Gh78Ij90Kl12");
const JWT = join("ey", "J", "abcdefgh.ijklmnop.qrst");
const ACCA_HEX = join("0F", "ACCA", "1234567890ABCDEF12");
const CORE = (s: string) => s.slice(6, 14);
const tok = (cat: string, n: number) => ["ANON", cat, String(n)].join("_");

function policy(redactSecrets = true, maskPublicIps = true): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets,
    maskPublicIps,
    categories: { ...on, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
function run(text: string, opts: { secrets?: boolean; mask?: boolean; custom?: CustomEntity[] } = {}) {
  const known = { hosts: [], accounts: [], internalDomains: [INTERNAL], custom: opts.custom };
  const a = createAnonymizer(policy(opts.secrets ?? true, opts.mask ?? true), known);
  const out = a.apply(text);
  const held = [...a.pairs().map((p) => p.value), ...a.discoveries().map((d) => d.value)];
  return { a, out, back: a.restore(out), held };
}
const holds = (held: string[], secret: string) => held.some((v) => v.includes(CORE(secret)));

describe.each([true, false])("a secret glued into an account or email, maskPublicIps=%s (#3006)", (mask) => {
  it("keeps the domain token of an internal UPN and hides the name one way", () => {
    const r = run(`logon bob${JWT}${AT}${INTERNAL} ok`, { mask });
    expect(r.out).toBe(`logon ${SEC}${AT}${tok("DOMAIN", 1)} ok`);
    expect(holds(r.held, JWT)).toBe(false);
    expect(r.a.discoveries()).toEqual([{ value: INTERNAL, category: "DOMAIN" }]);
  });

  // An sk- key glued after the name is found by the secret pass since #3029, so the rest of the
  // address goes with it, domain included (#3028).
  it("hides an internal UPN whole when the secret pass finds the key", () => {
    const r = run(`logon bob${SK}${AT}${INTERNAL} ok`, { mask });
    expect(r.out).toBe(`logon ${SEC} ok`);
    expect(holds(r.held, SK)).toBe(false);
    expect(r.a.discoveries()).toEqual([]);
  });

  it.each([SK, JWT])("hides an external email whole, its domain included (%#)", (secret) => {
    const r = run(`mail bob${secret}x${AT}${EXTERNAL} ok`, { mask });
    expect(r.out).toBe(`mail ${SEC} ok`);
    expect(r.out).not.toContain(EXTERNAL);
    expect(r.back).toBe(`mail ${SEC} ok`);
    expect(r.held).toEqual([]);
  });

  it("sends a bare repeat of a UPN name one way, in any letter case", () => {
    const name = `bob${SK}`;
    const r = run(`logon ${name}${AT}${INTERNAL} then ${name.toUpperCase()} again`, { mask });
    expect(r.out).toBe(`logon ${SEC} then ${SEC} again`); // the key is found by the secret pass (#3029)
    expect(holds(r.held, SK)).toBe(false);
  });

  it.each(["OTHER", "EMAIL", "USER"] as const)(
    "sends a %s custom value holding a glued key one way",
    (cat) => {
      const r = run(`seen bob${SK} here`, { mask, custom: [{ value: `bob${SK}`, category: cat }] });
      expect(r.out).toBe(`seen ${SEC} here`);
      expect(r.held).toEqual([]);
    },
  );

  it("hides an upper-case hex local part that holds an AWS-shaped run (masked either way)", () => {
    const r = run(`mail ${ACCA_HEX}${AT}${EXTERNAL} ok`, { mask });
    expect(r.out).toBe(`mail ${SEC} ok`);
  });

  it("leaves ordinary accounts and emails, and secret redaction turned off, as they were", () => {
    const plain = `logon CORP${BS}jsmith and jsmith${AT}${INTERNAL} mail j.doe${AT}${EXTERNAL}`;
    expect(run(plain, { mask }).out).toBe(
      `logon ${tok("DOMAIN", 1)}${BS}${tok("USER", 1)} and ${tok("USER", 1)}${AT}${tok("DOMAIN", 2)} mail ${tok("EMAIL", 1)}`,
    );
    const off = run(`mail bob${SK}${AT}${EXTERNAL} ok`, { mask, secrets: false });
    expect(off.out).toBe(`mail ${tok("EMAIL", 1)} ok`);
  });
});
