import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// Review findings on the glued-value passes. Each shape was masked on master and went out in clear on
// the branch: a decoder payload after a digit-prefixed -enc run, a SID before a glued address/card
// pair, and a phone number before a glued E.164 number. Synthetic values only, built at runtime.

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

function run(input: string, mask: boolean) {
  const a = createAnonymizer(policy(mask), { hosts: [], accounts: [], internalDomains: [] });
  const out = a.apply(input);
  return { out, back: a.restore(out) };
}

const BLOB = ["QUJDREVGR0hJ", "SktMTU5PUA"].join("");
const PAYLOAD = ["U3ludGhldGlj", "U2Vuc2l0aXZlUGF5bG9hZA=="].join("");
const NANP = ["212", "555", "0123"].join("-");
const E164 = ["+1555", "0100123"].join("");

describe("review: glued values stay masked as on master", () => {
  it.each([true, false])("masks the decoder payload after a digit-prefixed -enc run (public %s)", (mask) => {
    const input = `5-enc ${BLOB}-555-0123FromBase64String('${PAYLOAD}')`;
    const { out, back } = run(input, mask);
    expect(out).not.toContain(PAYLOAD.slice(0, 12));
    expect(out).toMatch(/\('ANON_CMD_\d+'\)$/);
    expect(back).toBe(input);
  });

  it("masks the decoder payload after an -enc run with a letter before the flag", () => {
    const input = `x -enc ${BLOB}FromBase64String('${PAYLOAD}')`;
    const { out, back } = run(input, true);
    expect(out).not.toContain(PAYLOAD.slice(0, 12));
    expect(out).not.toContain(BLOB);
    expect(back).toBe(input);
  });

  it.each([true, false])("keeps a SID before a glued address and card masked (public %s)", (mask) => {
    const sid = ["S-1-5-21", "123", "456", "789", "45"].join("-");
    const addr = ["10", "0", "1"].join(".");
    const input = `${sid}.${addr}${"4"}${"1".repeat(15)}`;
    const { out, back } = run(input, mask);
    expect(out).not.toContain("S-1-5-21");
    expect(out).not.toContain("123-456-789");
    expect(back).toBe(input);
  });

  it.each([true, false])("masks a phone number before a glued E.164 number (public %s)", (mask) => {
    const email = ["alice", ["example", "com"].join(".")].join("@");
    const head = ["8", "8", "8"].join(".");
    const input = `${email}${head}.${NANP}${E164}`;
    const { out, back } = run(input, mask);
    expect(out).not.toContain(NANP);
    expect(back).toBe(input);
  });

  it("masks a glued E.164 number after a masked phone number", () => {
    const input = `call ${NANP}${E164} now`;
    const { out, back } = run(input, true);
    expect(out).not.toContain(NANP);
    expect(out).not.toContain(E164);
    expect(back).toBe(input);
  });
});
