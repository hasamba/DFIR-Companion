import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3074: on a call seeded with a saved internal domain, the token-account reader took
// `<user>@<domain>N` first and never read the address behind it, so the middle of a double-@ address
// went out in clear; and a `+` phone prefix glued to `@<internal domain>` stayed outside the token.

const LOCAL = ["corp", "local"].join("."); // built at runtime: a synthetic internal domain
const MIDDLE = ["corp", "example15"].join(".");
const KNOWN: KnownEntities = { hosts: [], accounts: [], internalDomains: [LOCAL] };
const at = (...parts: string[]) => parts.join("@"); // built at runtime
const PHONE = ["+972", "501234567", "5"].join("");

function policy(maskPublicIps: boolean): AnonPolicy {
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
      PHONE: true,
      NATID: true,
    },
  };
}

function seeded(seed: string, text: string, mask: boolean) {
  const first = createAnonymizer(policy(mask), KNOWN);
  first.apply(seed);
  const a = createAnonymizer(policy(mask), { ...KNOWN, custom: first.discoveries() });
  const out = a.apply(text);
  return { out, back: a.restore(out) };
}

describe.each([true, false])(
  "seeded double-@ and phone-prefix accounts (#3074), maskPublicIps=%s",
  (mask) => {
    it.each([
      ["a glued-digit address", `ref ${at("jdoe", LOCAL)}1 end`],
      ["the bare domain", `ref ${LOCAL} end`],
    ])("masks the middle of a double-@ address after %s was saved", (_label, seed) => {
      const text = `x ${at("bob", MIDDLE, LOCAL)} y`;
      const { out, back } = seeded(seed, text, mask);
      expect(out).not.toContain(MIDDLE);
      expect(out).not.toContain(LOCAL);
      expect(out).toMatch(/^x bob@ANON_EMAIL_\d+ y$/);
      expect(back).toBe(text);
    });

    it("leaves a first half the email pass reads to that pass, so its user stays masked", () => {
      const text = `x ${at("bob", ["corp", "example"].join("."), LOCAL)} y`;
      const { out, back } = seeded(`ref ${LOCAL} end`, text, mask);
      expect(out).toMatch(/^x ANON_EMAIL_\d+@ANON_DOMAIN_\d+ y$/);
      expect(back).toBe(text);
    });

    it.each(["", "x "])(
      "keeps the + of a phone glued to the internal domain inside the token (%j)",
      (lead) => {
        const text = `${lead}${at(PHONE, LOCAL)}`;
        const { out, back } = seeded("a Corp\\zed x", text, mask);
        expect(out).not.toContain("+");
        expect(out).not.toMatch(/\d{4}/);
        expect(out).not.toContain(LOCAL);
        expect(back).toBe(text);
      },
    );
  },
);
