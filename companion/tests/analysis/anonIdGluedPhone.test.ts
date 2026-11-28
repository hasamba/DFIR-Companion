import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3075: a phone number glued straight after an e-mail address, an internal account or a host name
// went out in clear. The phone pass runs last, when the address is already a token ending in a digit,
// and the E.164 guard refused a "+" after a digit. The phone gets its own token; the address before it
// restores exactly. Synthetic values only; addresses are built at runtime.

const AT = "@";
const DOM = ["corp", "local"].join(".");
const EXT = ["internal", "example"].join(".");
const PHONE = ["+1555", "0100123"].join("");

function policy(maskPublicIps: boolean, PHONE_ON = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps,
    categories: {
      IP: true,
      EMAIL: true,
      USER: true,
      HOST: true,
      DOMAIN: true,
      PATH: true,
      CMD: true,
      REG: true,
      CARD: true,
      PHONE: PHONE_ON,
      NATID: true,
    },
  };
}

function run(input: string, mask: boolean, phoneOn = true) {
  const a = createAnonymizer(policy(mask, phoneOn), {
    hosts: ["srv01"],
    accounts: ["jdoe"],
    internalDomains: [DOM],
  });
  const out = a.apply(input);
  return { out, back: a.restore(out), pairs: a.pairs() };
}

describe("a phone glued after an address or account (#3075)", () => {
  const shapes: [string, string][] = [
    ["external e-mail", `x bob${AT}${EXT}${PHONE} y`],
    ["internal e-mail", `x bob${AT}${DOM}${PHONE} y`],
    ["known account e-mail", `x jdoe${AT}${DOM}${PHONE} y`],
    ["DOMAIN\\account", `x CORP\\jdoe${PHONE} y`],
    ["host FQDN", `x srv01.${DOM}${PHONE} y`],
    ["bare internal domain", `x ${DOM}${PHONE} y`],
  ];
  for (const mask of [true, false]) {
    for (const [name, input] of shapes) {
      it(`${name} (maskPublicIps=${mask}): the phone is its own token and both restore`, () => {
        const { out, back, pairs } = run(input, mask);
        expect(out).not.toContain(PHONE.slice(1));
        expect(out).toMatch(/ANON_PHONE_\d+ y$/);
        expect(pairs.some((p) => p.token.startsWith("ANON_PHONE_") && p.value === PHONE)).toBe(true);
        expect(back).toBe(input);
      });
    }
  }

  it("masks the phone after an address left in clear (e-mail and domain categories off)", () => {
    const p = policy(true);
    const a = createAnonymizer(
      { ...p, categories: { ...p.categories, EMAIL: false, DOMAIN: false, USER: false } },
      { hosts: [], accounts: [], internalDomains: [DOM] },
    );
    for (const input of [`x bob${AT}${EXT}${PHONE} y`, `x bob${AT}${DOM}${PHONE} y`]) {
      const out = a.apply(input);
      expect(out).toMatch(/ANON_PHONE_\d+ y$/);
      expect(out).not.toContain(PHONE.slice(1));
      expect(a.restore(out)).toBe(input);
    }
  });

  it("masks the phone after a custom value", () => {
    const custom = [{ value: "acmeproj", category: "OTHER" as const }];
    const a = createAnonymizer(policy(false), { hosts: [], accounts: [], internalDomains: [], custom });
    const input = `x acmeproj${PHONE} y`;
    const out = a.apply(input);
    expect(out).toMatch(/^x ANON_OTHER_\d+ANON_PHONE_\d+ y$/);
    expect(a.restore(out)).toBe(input);
  });

  it("keeps a profile name holding an address and glued phone as one user token", () => {
    const profile = ["C:", "Users", ""].join("\\");
    const input = `${profile}jdoe0 x${AT}${DOM}${PHONE}`;
    const { out, back } = run(input, true);
    expect(out.startsWith(profile)).toBe(true);
    expect(out.slice(profile.length)).toMatch(/^ANON_USER_\d+$/);
    expect(back).toBe(input);
  });

  it("leaves the phone alone when phone masking is off", () => {
    const input = `x bob${AT}${EXT}${PHONE} y`;
    const { out, back } = run(input, true, false);
    expect(out).toContain(PHONE);
    expect(back).toBe(input);
  });

  it("keeps module+offset and SemVer build metadata as they were", () => {
    for (const input of ["kernel32.dll+1245184 offset", "release 1.0.0+20130313144700 metadata"]) {
      expect(run(input, true).out).toBe(input);
    }
  });

  it("does not change a port or short glued digits after an address", () => {
    const port = run(`x bob${AT}${DOM}:8080 y`, true).out;
    expect(port).toMatch(/^x ANON_USER_\d+@ANON_DOMAIN_\d+:8080 y$/);
    expect(run(`x bob${AT}${DOM}+123 y`, true).out).toMatch(/\+123 y$/);
  });
});
