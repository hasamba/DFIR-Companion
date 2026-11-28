import { describe, it, expect } from "vitest";
import { redactSecretText } from "../../src/analysis/anonSecrets.js";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3029: a secret key with digits glued in front (007password=<value>) was not read as a key, and an
// OpenAI key glued after an account or host name (CORP\bob + sk-<key>) was not found, so the account
// pass took "bobsk" as the user and the key body went to the AI in clear. Every secret-shaped value is
// assembled at runtime, so no secret-shaped literal sits in the repo (like previewDiff.test.ts).
const join = (...parts: string[]) => parts.join("");
const BS = String.fromCharCode(0x5c);
const VALUE = join("Sup3r", "S3cret", "Value99");
const PW = join("pass", "word");
const SK = join("s", "k-", "Ab12Cd34Ef56Gh78Ij90Kl12");
const INTERNAL = join("contoso", ".local");
const HOME = ["", "home", ""].join("/");

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

function run(text: string, mask = true) {
  const a = createAnonymizer(policy(mask), known());
  const out = a.apply(text);
  const held = [...a.pairs().map((p) => p.value), ...a.discoveries().map((d) => d.value)];
  return { out, held };
}

describe("a key with digits glued in front (#3029)", () => {
  it("redacts the value one way", () => {
    expect(redactSecretText(`007${PW}=${VALUE} end`)).toBe(`007${PW}=${SEC} end`);
    expect(redactSecretText(`x 12token: ${VALUE}`)).toBe(`x 12token: ${SEC}`);
  });

  it.each([true, false])("sends no part of the value out, maskPublicIps=%s", (mask) => {
    for (const text of [`007${PW}=${VALUE}`, `CORP${BS}007${PW}=${VALUE}`, `${HOME}007${PW}=${VALUE}`]) {
      const r = run(text, mask);
      expect(r.out).not.toContain(VALUE.slice(0, 8));
      expect(r.held.some((v) => v.includes(VALUE.slice(0, 8)))).toBe(false);
    }
  });
});

describe.each([true, false])("an sk- key glued after a name, maskPublicIps=%s (#3029)", (mask) => {
  it.each([
    ["an account", `logon CORP${BS}bob${SK} ok`],
    ["a host name", `host bob${SK}.${INTERNAL} ok`],
    ["a profile path", `C:${BS}Users${BS}bob${SK}${BS}AppData ok`],
  ])("sends %s one way", (_n, text) => {
    const r = run(text, mask);
    expect(r.out).toContain(SEC);
    expect(r.out).not.toContain(SK.slice(6, 14));
    expect(r.out).not.toContain("bob");
    expect(r.held.some((v) => v.includes(SK.slice(6, 14)))).toBe(false);
  });

  it("leaves names that only look like one readable", () => {
    for (const name of [
      "kiosk-FrontDesk01",
      "desk-OperatorWorkstation01",
      "task-Ab12Cd34",
      "disk-0123456789abcdef0123",
    ])
      expect(redactSecretText(`host ${name} ok`)).toBe(`host ${name} ok`);
  });
});
