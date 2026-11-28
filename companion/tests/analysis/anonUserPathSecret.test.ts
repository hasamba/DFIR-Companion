import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3002: the profile-path pass runs after secrets became the one-way secret sentinel (U+E001), and
// the username part of a profile path ran on over it. The secret vanished into the user token (the
// AI never saw [REDACTED_SECRET]), restore() handed back the raw sentinel, and the saved USER value
// held it. The name now ends at the secret and each part is its own USER token. No part is learned
// or saved: a saved fragment such as "5" cut a SID apart on a later call. Synthetic values only.

// Prefixes, names and secret shapes are assembled at runtime, so no path- or secret-shaped literal
// sits in the repo for the publish scan to read as real (like previewDiff.test.ts).
const BS = String.fromCharCode(0x5c);
const WIN = ["C:", "Users", ""].join(BS);
const HOME = ["", "home", ""].join("/");
const DOMAIN = ["corp", "local"].join(".");
const BOB = ["b", "ob"].join("");
const AWS = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");
const GHP = ["ghp", "_", "abcdefghijKLMNOPQRST0123456789"].join("");
const PASSWORD = ["pass", "word=", "Hunter2Value99"].join("");
const TOKEN = ["tok", "en=", "Zq9Wx8Vu7Ts6"].join("");
const U = (n: number) => ["ANON", "USER", String(n)].join("_");
const IP1 = ["ANON", "IP", "1"].join("_");
const SEC = SECRET_PLACEHOLDER;
const SENTINEL = String.fromCharCode(0xe001);
const IPV6_SENTINEL = String.fromCharCode(0xe000);

function policy(maskPublicIps: boolean, redactSecrets = true): AnonPolicy {
  return {
    enabled: true,
    redactSecrets,
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
const known = (): KnownEntities => ({ hosts: [], accounts: [], internalDomains: [DOMAIN] });
const run = (text: string, mask: boolean, secrets = true) => {
  const a = createAnonymizer(policy(mask, secrets), known());
  const out = a.apply(text);
  return { out, back: a.restore(out), values: a.discoveries().map((d) => d.value) };
};
const clean = (s: string) => !s.includes(SENTINEL) && !s.includes(IPV6_SENTINEL);

describe.each([true, false])("a secret inside a profile name, maskPublicIps=%s (#3002)", (mask) => {
  it("ends the username at the secret and masks the text after it as its own token", () => {
    const text = `4624 ${WIN}${BOB} ${AWS} zqmarker end`;
    const r = run(text, mask);
    expect(r.out).toBe(`4624 ${WIN}${U(1)} ${SEC} ${U(2)}`);
    expect(r.back).toBe(`4624 ${WIN}${BOB} ${SEC} zqmarker end`);
    expect(r.values).toEqual([]);
  });

  it.each([AWS, GHP, PASSWORD, TOKEN])("shows %s as [REDACTED_SECRET], never in clear", (secret) => {
    const r = run(`${WIN}${BOB} ${secret} zqmarker`, mask);
    expect(r.out).toContain(SEC);
    expect(r.out).not.toContain(secret);
    expect(r.out).not.toContain("zqmarker");
    expect(clean(r.out) && clean(r.back)).toBe(true);
    expect(r.values.every(clean)).toBe(true);
    expect(r.values.some((v) => v.includes("zqmarker"))).toBe(false);
  });

  it("masks a glued key=value secret and keeps the username before it", () => {
    const r = run(`${HOME}${BOB},${PASSWORD} end`, mask);
    expect(r.out.startsWith(`${HOME}${U(1)}`)).toBe(true);
    expect(r.out).toContain(SEC);
    expect(r.out).not.toContain("end");
    expect(r.values.every(clean)).toBe(true);
    expect(r.values.some((v) => v.includes("end"))).toBe(false);
  });

  it("splits at every secret and saves none of the parts", () => {
    const r = run(`${WIN}${BOB} ${AWS} mid ${GHP} tail`, mask);
    expect(r.out).toBe(`${WIN}${U(1)} ${SEC} ${U(2)} ${SEC} ${U(3)}`);
    expect(r.back).toBe(`${WIN}${BOB} ${SEC} mid ${SEC} tail`);
    expect(r.values).toEqual([]);
  });

  it("never learns a part of the name as a bare word", () => {
    const r = run(`${WIN}${BOB} ${AWS} zqmarker${"\n"}zqmarker was here`, mask);
    expect(r.out).toBe(`${WIN}${U(1)} ${SEC} ${U(2)}${"\n"}zqmarker was here`);
  });

  it.each(["S-1-5-21-1-2-3-4 x", "seen fd00::10.168.1.5 here"])(
    "a name split by a secret is never saved to cut %s on a later call",
    (later) => {
      const first = createAnonymizer(policy(mask), known());
      first.apply(`${WIN}5 ${AWS} x`);
      expect(first.discoveries()).toEqual([]);
      const seeded = createAnonymizer(policy(mask), { ...known(), custom: first.discoveries() });
      expect(seeded.apply(later)).toBe(createAnonymizer(policy(mask), known()).apply(later));
    },
  );

  it("keeps a built-in profile name before a secret as a USER token", () => {
    const r = run(`${WIN}Public ${AWS} x`, mask);
    expect(r.out).toBe(`${WIN}${U(1)} ${SEC} ${U(2)}`);
    expect(r.back).toBe(`${WIN}Public ${SEC} x`);
  });

  it("never saves the single OCR word after a secret", () => {
    const r = run(`${WIN}${AWS},end`, mask);
    expect(r.out).toBe(`${WIN}${SEC}${U(1)}`);
    expect(r.back).toBe(`${WIN}${SEC},end`);
    expect(r.values).toEqual([]);
  });

  // The #3000 rule and this one together: an address after the secret keeps its own token, and the
  // built-in name before the secret stays masked.
  it("handles a built-in name, a secret and an address together", () => {
    const text = `${WIN}Public ${AWS} fd00::2 x`;
    const r = run(text, mask);
    expect(r.out).toBe(`${WIN}${U(1)} ${SEC} ${IP1} x`);
    expect(r.back).toBe(`${WIN}Public ${SEC} fd00::2 x`);
    expect(r.values).toContain("fd00::2");
    expect(r.values.every(clean)).toBe(true);
  });

  it("handles a name, a secret, a word and an address together", () => {
    const text = `${WIN}${BOB} ${AWS} w fd00::2`;
    const r = run(text, mask);
    expect(r.out).toBe(`${WIN}${U(1)} ${SEC} ${U(2)} ${IP1}`);
    expect(r.back).toBe(`${WIN}${BOB} ${SEC} w fd00::2`);
    expect(r.values).toEqual(["fd00::2"]);
  });

  it("leaves a profile path with no secret unchanged", () => {
    expect(run(`${WIN}${BOB}${BS}x`, mask).out).toBe(`${WIN}${U(1)}${BS}x`);
    expect(run(`${WIN}${BOB} zqmarker end`, mask, false).out).toBe(`${WIN}${U(1)}`);
    expect(run(`${WIN}Public${BS}x`, mask).out).toBe(`${WIN}Public${BS}x`);
  });
});
