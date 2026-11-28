import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3050: an e-mail address with a digit glued to its end (a log field run into the next value) went to
// the AI in clear, even on a known internal domain. Addresses are built at runtime.
const AT = "@";
const DOM = ["corp", "local"].join(".");
const EXT = ["example", "com"].join(".");

function policy(over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps: true,
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
      ...over,
    },
  };
}
const make = (over: Partial<AnonPolicy["categories"]> = {}) =>
  createAnonymizer(policy(over), { hosts: [], accounts: [], internalDomains: [DOM], usernames: ["jdoe"] });

describe("an e-mail address with a digit glued to its end (#3050)", () => {
  it("masks an internal address of a known user, user and domain, and restores it", () => {
    for (const tail of ["0|x", "12 x", "7"]) {
      const a = make();
      const text = `mail from jdoe${AT}${DOM}${tail}`;
      const out = a.apply(text);
      expect(out).not.toContain("jdoe");
      expect(out.toLowerCase()).not.toContain(DOM);
      expect(a.restore(out)).toBe(text);
    }
  });

  it("gives an unknown user on an internal domain a USER token and learns the name", () => {
    const a = make();
    const text = `zed${AT}${DOM}0|x then zed logged on`;
    const out = a.apply(text);
    expect(out).not.toMatch(/zed/i);
    expect(out).toMatch(/ANON_USER_\d+/);
    expect(a.restore(out)).toBe(text);
  });

  it("masks an external address and keeps the digit after it", () => {
    const a = make();
    const text = `bob${AT}${EXT}0|x`;
    const out = a.apply(text);
    expect(out).not.toContain(`bob${AT}`);
    expect(out).toMatch(/ANON_EMAIL_\d+.?0\|x$/u);
    expect(a.restore(out)).toBe(text);
  });

  it("leaves a digit run that goes on into another address to the old reading", () => {
    const a = make();
    const text = `jdoe${AT}${DOM}5${AT}${DOM}`;
    const out = a.apply(text);
    expect(out).not.toContain("jdoe");
    expect(a.restore(out)).toBe(text);
  });

  it("never takes the tail of a card or a long digit run a later pass masks", () => {
    const card = ["4111", "1111", "1111", "1111"].join(" ");
    for (const text of [`${card}.0.0.5a${AT}mail.server01 x`, `zed${AT}${DOM}123456782|x`]) {
      const a = make();
      const out = a.apply(text);
      expect(out).not.toContain("1111 1111");
      expect(out).not.toContain("123456782");
      expect(a.restore(out)).toBe(text);
    }
  });
});
