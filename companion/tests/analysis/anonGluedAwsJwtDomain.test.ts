import { describe, it, expect } from "vitest";
import { redactSecretText } from "../../src/analysis/anonSecrets.js";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3041: an AWS key glued to a digit on either side went to the AI in clear; a JWT glued after a
// dotless e-mail domain or after DOMAIN\user, and a key glued inside an e-mail or UPN domain label,
// were held in a reversible token or partly in clear. Every secret-shaped value is assembled at
// runtime, so no secret-shaped literal sits in the repo (like previewDiff.test.ts).
const join = (...parts: string[]) => parts.join("");
const AT = String.fromCharCode(0x40);
const BS = String.fromCharCode(0x5c);
const AWS = join("AK", "IA", "QZ7WXCVBNMLKJHGF");
const HEADER_ONLY = join("ey", "J", "abcdefgh.ijklmnop.qrst"); // payload not eyJ, short signature
const LONG_SIG = join("ey", "J", "abcdefgh.ijklmnop.", "Sf1KxwRJSMeK9abcQ"); // payload not eyJ
const INTERNAL = join("contoso", ".local");
const CORP = join(".", "corp", ".local"); // a synthetic internal suffix, built at runtime
const cores = (s: string) => s.split(".").map((g) => g.slice(3, 9));

function policy(maskPublicIps: boolean): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: { ...on, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
const known = (): KnownEntities => ({ hosts: [], accounts: [], internalDomains: [INTERNAL] });

function run(text: string, mask: boolean) {
  const a = createAnonymizer(policy(mask), known());
  const out = a.apply(text);
  const held = [...a.pairs().map((p) => p.value), ...a.discoveries().map((d) => d.value)];
  return { out, held, back: a.restore(out) };
}
function expectOneWay(text: string, secret: string, mask: boolean) {
  const r = run(text, mask);
  expect(r.out).toContain(SEC);
  for (const c of cores(secret.length === 20 ? secret.slice(4) : secret)) {
    expect(r.out).not.toContain(c);
    expect(r.back).not.toContain(c);
    expect(r.held.some((v) => v.includes(c))).toBe(false);
  }
}

describe("an AWS key glued to a digit on either side (#3041)", () => {
  it.each([
    [`${AWS}9`, SEC],
    [`id ${AWS}2024 end`, `id ${SEC} end`],
    [`20240101T1200${AWS}`, SEC],
    [`ts=20240101T1200${AWS} ok`, `ts=${SEC} ok`],
    [`X9${AWS}`, SEC],
  ])("redacts %s one way", (text, want) => {
    expect(run(text, true).out).toBe(want);
  });

  it("leaves a base32-looking word with digits, and upper-case hex, readable", () => {
    const hexAcca = join("20240101T", "1200", "ACCA", "0123456789ABCDEF"); // hex body, no G-Z
    for (const text of [
      "ACCAPAYABLESARCHIVE2023.zip", // the digit ends the body: WORD + digits
      `host=ASIAPACIFICREGIONSRV01${CORP}`,
      "ASIAPACIFICFILESRV0123",
      join("AK", "IA", "QZ8WXCVBNMLKJHG9", "5"), // 8 and 9 are no base32 digits
      hexAcca,
      `${hexAcca}9`,
    ])
      expect(redactSecretText(text)).toBe(text);
  });
});

describe.each([true, false])(
  "a JWT glued after a dotless e-mail domain, maskPublicIps=%s (#3041)",
  (mask) => {
    it.each([
      ["localhost", `user svc${AT}localhost${HEADER_ONLY} end`],
      ["a digit-bearing signature", `svc${AT}localhost${join("ey", "J", "abcdefgh.ijklmnop.abcdEFGH1234")}`],
      ["an internal name", `svc${AT}intranet${HEADER_ONLY}`],
      ["any dotless host, long signature", `svc${AT}dc01${LONG_SIG}`],
    ])("sends %s and the token one way", (_n, text) => {
      expectOneWay(text, text.slice(text.indexOf("eyJ")).split(" ")[0], mask);
      expect(run(text, mask).out).not.toContain("svc");
    });
  },
);

describe.each([true, false])("a JWT glued after DOMAIN\\user, maskPublicIps=%s (#3041)", (mask) => {
  it("sends the account and a token with a long mixed signature one way", () => {
    const r = run(`logon CORP${BS}bob${LONG_SIG} ok`, mask);
    expect(r.out).toBe(`logon ${SEC} ok`);
    expectOneWay(`logon CORP${BS}bob${LONG_SIG} ok`, LONG_SIG, mask);
  });
});

describe.each([true, false])(
  "a key glued inside an e-mail domain label, maskPublicIps=%s (#3041)",
  (mask) => {
    it.each([
      ["an external address", `from bob${AT}SRV${AWS}.example.com`],
      ["an internal UPN", `logon bob${AT}SRV${AWS}.${INTERNAL} ok`],
      ["a subdomain", `bob${AT}mail.SRV${AWS}x${CORP}`],
    ])("sends %s whole one way", (_n, text) => {
      expectOneWay(text, AWS, mask);
      expect(run(text, mask).out).not.toContain("bob");
    });

    it("leaves host labels that only look like a key or a token readable", () => {
      for (const text of [
        `x${AT}ASIAPACIFICFILESERVER01.CORP.COM`,
        `x${AT}disk-01234567890123456789012${CORP}`,
        `mail x${AT}turkeyJerky01.${INTERNAL}`,
        `x${AT}monkeyJump_ab12cd.${INTERNAL}`,
        `Reports${BS}surveyJanuary2024.backup.xlsx`,
      ])
        expect(redactSecretText(text)).toBe(text);
    });

    it("stays fast on a long dotted domain", () => {
      const text = `x${AT}${"ab.".repeat(40_000)}com`;
      const t = performance.now();
      expect(redactSecretText(text)).toBe(text);
      expect(performance.now() - t).toBeLessThan(1000);
    });
  },
);
