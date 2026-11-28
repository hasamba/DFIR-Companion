import { describe, it, expect } from "vitest";
import { redactSecretText } from "../../src/analysis/anonSecrets.js";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3044: the glued legacy sk- check (#3003) read any 20 characters after "sk-" as a key, so a name
// such as disk-0123... was redacted; and a glued legacy sk- key in a UPN domain label was held in a
// reversible DOMAIN token. Every secret-shaped value is assembled at runtime (like previewDiff.test.ts).
const join = (...parts: string[]) => parts.join("");
const AT = String.fromCharCode(0x40);
const BS = String.fromCharCode(0x5c);
const INTERNAL = join("contoso", ".local");
const EXTERNAL = join("exa", "mple", ".com");
const HOME = join("C:", BS, "Users", BS);
const SK = (body: string) => join("s", "k-", body);
const MIXED = SK("Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0UvWxYz12AbCdEfGh");
const HEX32 = SK("0123456789abcdef0123456789abcdef");
const LOWER38 = SK("abcdefghijklmnopqrstuvwxyz0123456789ab");
const DIGITS = join("di", "sk-", "01234567890123456789012");

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
function expectOneWay(text: string, key: string, mask: boolean) {
  const r = run(text, mask);
  const core = key.slice(5, 17);
  expect(r.out).toContain(SEC);
  expect(r.out).not.toContain(core);
  expect(r.back).not.toContain(core);
  expect(r.held.some((v) => v.includes(core))).toBe(false);
}

describe.each([true, false])("glued legacy sk- bodies, maskPublicIps=%s (#3044)", (mask) => {
  it("leaves a digit-only sk- name a reversible name", () => {
    for (const text of [
      `${HOME}${DIGITS}${BS}Desktop`,
      `mail ${DIGITS}${AT}${INTERNAL} ok`,
      `mail ${DIGITS}${AT}${EXTERNAL} ok`,
      `${HOME}x${join("ta", "sk-", "98765432109876543210")}${BS}a`,
    ]) {
      const r = run(text, mask);
      expect(r.out).not.toContain(SEC);
      expect(r.out).toMatch(/ANON_(USER|EMAIL)_\d+/);
      expect(r.back).toBe(text);
    }
  });

  it.each([
    ["mixed", MIXED],
    ["32 hex", HEX32],
    ["38 lower and digits", LOWER38],
    ["48 lower letters", SK("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv")],
    ["48 mixed letters, no digit", SK("AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv")],
    ["22 lower and digits", SK("abcdefghij0123456789ab")],
    ["20 hex", SK("0123456789abcdef0123")],
  ])("keeps a real %s key glued in a name one way", (_n, key) => {
    expectOneWay(`${HOME}bob${key}${BS}Desktop`, key, mask);
    expectOneWay(`mail bob${key}${AT}${EXTERNAL} ok`, key, mask);
    expectOneWay(`logon bob${key}${AT}${INTERNAL} ok`, key, mask);
  });

  it.each([
    ["32 hex", HEX32],
    ["38 lower and digits", LOWER38],
  ])("sends a UPN whose domain holds a glued %s key one way, whole", (_n, key) => {
    for (const text of [
      `logon bob${AT}SRV${key}.${INTERNAL} ok`,
      `logon bob${AT}${"A".repeat(60)}${key}.${INTERNAL} ok`,
      `logon bob${AT}${"a.".repeat(18)}x${key}.${INTERNAL} ok`,
    ]) {
      expectOneWay(text, key, mask);
      expect(run(text, mask).out).toBe(`logon ${SEC} ok`);
    }
  });
});

describe("host labels that only look like an sk- key (#3044)", () => {
  it("stay readable in an e-mail domain", () => {
    for (const host of ["kiosk-frontdesklobbyscreen0123", "desk-OperatorWorkstation01", DIGITS]) {
      const text = `x${AT}${host}.${INTERNAL}`;
      expect(redactSecretText(text)).toBe(text);
    }
  });
});
