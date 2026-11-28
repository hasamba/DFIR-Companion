import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3039: a credential value that is itself an account, an internal e-mail or a profile path was
// redacted one way before the account, e-mail and path passes ran, so the user in it was never
// learned and a bare mention of that user elsewhere went to the AI in clear. Only the user name is
// learned, never the value. Synthetic values only, assembled at runtime.
const join = (...parts: string[]) => parts.join("");
const AT = String.fromCharCode(0x40);
const BS = String.fromCharCode(0x5c);
const DOMAIN = join("corp", ".local");
const USER = "jdoe";
const MAIL = join(USER, AT, DOMAIN);
const SK = join("sk", "_live_", "Ab12Cd34Ef56Gh78Ij90");

function policy(maskPublicIps: boolean, redactSecrets = true): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets,
    maskPublicIps,
    categories: { ...on, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
const known = (): KnownEntities => ({ hosts: [], accounts: [], internalDomains: [DOMAIN] });

function run(text: string, mask: boolean, secrets = true) {
  const a = createAnonymizer(policy(mask, secrets), known());
  const out = a.apply(text);
  const held = [...a.pairs().map((p) => p.value), ...a.discoveries().map((d) => d.value)];
  return { a, out, held, back: a.restore(out) };
}

const VALUES: [string, string][] = [
  ["keyed internal e-mail", `password=${MAIL}`],
  ["keyed DOMAIN\\user", `password=CORP${BS}${USER}`],
  [
    "registry data profile path",
    `New-ItemProperty HKLM:${BS}x -Name DefaultPassword -Value C:${BS}Users${BS}${USER}`,
  ],
  ["JSON registry data e-mail", `{"ValueName":"DefaultPassword","ValueData":"${MAIL}"}`],
  ["reg add data e-mail", `reg add "HKLM${BS}x y" /v DefaultPassword /d ${MAIL} /f`],
  [
    "JSON-escaped profile path",
    `{"ValueName":"DefaultPassword","ValueData":"C:${BS}${BS}Users${BS}${BS}${USER}"}`,
  ],
  ["e-mail ending at punctuation", `password=${MAIL}; next`],
];

describe.each([true, false])(
  "a user inside a redacted value is learned, maskPublicIps=%s (#3039)",
  (mask) => {
    it.each(VALUES)("%s: a bare mention before or after is masked", (_n, value) => {
      for (const text of [`${USER} logged on${"\n"}${value}`, `${value}${"\n"}seen ${USER} again`]) {
        const r = run(text, mask);
        expect(r.out).toContain(SEC);
        expect(r.out).not.toMatch(/\bjdoe\b/);
        expect(r.out).toMatch(/ANON_USER_\d+/);
        // only the user name is held, never the value
        expect(r.held).toContain(USER);
        expect(r.held.some((v) => v !== USER && v.toLowerCase().includes(USER))).toBe(false);
        expect(r.back).toContain(SEC);
        expect(r.back).not.toContain(MAIL);
      }
    });

    it("a later call on the same anonymizer still masks the bare user", () => {
      const r = run(`password=${MAIL}`, mask);
      expect(r.a.apply(`then ${USER} left`)).not.toMatch(/\bjdoe\b/);
    });

    it("a password that only holds a backslash teaches nothing", () => {
      const r = run(`password=P${AT}ss${BS}w0rdX9${"\n"}w0rdX9 here`, mask);
      expect(r.held.some((v) => v.includes("w0rd"))).toBe(false);
    });

    it("a bare value or an external e-mail is not a learned entity", () => {
      for (const value of [`password=${USER}`, `password=${join(USER, AT, "gm", "ail", ".com")}`]) {
        const r = run(`${value}${"\n"}${USER} here`, mask);
        expect(r.held).not.toContain(USER);
      }
    });

    it("a user name that holds a secret is never learned into a token", () => {
      const value = `New-ItemProperty HKLM:${BS}x -Name DefaultPassword -Value C:${BS}Users${BS}bob${SK}`;
      const r = run(`${value}${"\n"}bob${SK} here`, mask);
      expect(r.out).not.toContain(SK.slice(8));
      expect(r.held.some((v) => v.includes(SK.slice(8)))).toBe(false);
    });

    it("a short or digit-only user name is never learned (#3030)", () => {
      for (const user of ["2024", "ab"]) {
        const r = run(`password=CORP${BS}${user}${"\n"}seen ${user} here`, mask);
        expect(r.held).not.toContain(user);
      }
    });

    it("reads an e-mail value only up to an IPv6 address glued after it", () => {
      const r = run(`password=${MAIL}fd00::2${"\n"}seen ${USER} here`, mask);
      expect(r.out).not.toMatch(/\bjdoe\b/);
      expect(r.held).toContain(USER);
    });

    it("with secrets off the output is unchanged (the user is masked by the account passes)", () => {
      const r = run(`${USER} x${"\n"}password=${MAIL}`, mask, false);
      expect(r.out).not.toMatch(/\bjdoe\b/);
    });
  },
);
