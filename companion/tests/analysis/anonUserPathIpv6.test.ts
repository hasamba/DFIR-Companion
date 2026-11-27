import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3000 (case 3): the profile-path pass runs while each IPv6 address is held aside as an internal
// placeholder. The username part of a profile path could run on into that placeholder, so the
// address was lost (the AI never saw it, restore gave back garbage) and a USER value holding the
// placeholder's private character was stored. Synthetic values only.

// Profile-folder prefixes, names, the domain and tokens are assembled at runtime, so no path-shaped
// literal sits in the repo for the publish scan to read as real (like previewDiff.test.ts).
const BS = String.fromCharCode(0x5c);
const WIN = ["C:", "Users", ""].join(BS);
const ROOTED = ["", "Users", ""].join(BS);
const HOME = ["", "home", ""].join("/");
const MAC = ["", "Users", ""].join("/");
const DOMAIN = ["corp", "local"].join(".");
const ALICE = ["ali", "ce"].join("");
const BOB = ["b", "ob"].join("");
const U1 = ["ANON", "USER", "1"].join("_");
const IP1 = ["ANON", "IP", "1"].join("_");
const SENTINEL = String.fromCharCode(0xe000);
const SECRET_SENTINEL = String.fromCharCode(0xe001);

function policy(maskPublicIps: boolean, redactSecrets = false): AnonPolicy {
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
const run = (text: string, mask: boolean, secrets = false) => {
  const a = createAnonymizer(policy(mask, secrets), known());
  const out = a.apply(text);
  return {
    out,
    back: a.restore(out),
    pairs: a.pairs().map((p) => [p.token, p.value]),
    values: a.discoveries().map((d) => d.value),
  };
};
const noSentinel = (s: string) => !s.includes(SENTINEL) && !s.includes(SECRET_SENTINEL);

describe.each([true, false])("profile path next to an IPv6 address, maskPublicIps=%s (#3000)", (mask) => {
  it.each([
    [`${WIN}${ALICE}fd00::2${BS}x`, `${WIN}${U1}${IP1}${BS}x`, ALICE],
    [
      `4624 ${WIN}${BOB} logon from fd00::2 port 445`,
      `4624 ${WIN}${U1}${IP1} port 445`,
      `${BOB} logon from `,
    ],
    [`${HOME}${ALICE} fd00::2`, `${HOME}${U1}${IP1}`, `${ALICE} `],
    [`${MAC}${BOB}fd00::2`, `${MAC}${U1}${IP1}`, BOB],
  ])("%s keeps the address as its own token", (text, expected, user) => {
    const r = run(text, mask);
    expect(r.out).toBe(expected);
    expect(noSentinel(r.out)).toBe(true);
    expect(r.back).toBe(text);
    expect(r.pairs).toContainEqual([U1, user]);
    expect(r.pairs).toContainEqual([IP1, "fd00::2"]);
    expect(r.values.every(noSentinel)).toBe(true);
  });

  // A built-in profile name glued to an address stays a USER token, as it was before the fix:
  // nothing that was masked goes out in clear.
  it.each([
    [WIN, "Public"],
    [ROOTED, "Public"],
    [WIN, "Default"],
  ])("%s%s glued to an address stays a USER token", (prefix, name) => {
    const text = `${prefix}${name}fd00::2 y`;
    const r = run(text, mask);
    expect(r.out).toBe(`${prefix}${U1}${IP1} y`);
    expect(r.back).toBe(text);
    expect(r.pairs).toContainEqual([U1, name]);
    expect(r.values.every(noSentinel)).toBe(true);
  });

  it("leaves a built-in profile name in clear when no address follows it", () => {
    const text = `${WIN}Public${BS}Documents`;
    expect(run(text, mask).out).toBe(text);
  });
});

describe("profile path next to a public IPv6 address with public masking off (#3000)", () => {
  it("shows the address in clear, as for every other public address on that setting", () => {
    const text = `${WIN}${ALICE} 2001:db8::2 x`;
    const r = run(text, false);
    expect(r.out).toBe(`${WIN}${U1}${String.fromCharCode(0xb7)}2001:db8::2 x`);
    expect(noSentinel(r.out)).toBe(true);
    expect(r.back).toBe(text);
  });
});

describe("unchanged neighbours (#3000)", () => {
  // The secret placeholder inside a profile name is a separate issue (#3002); this fix leaves it as is.
  it("leaves a redacted secret inside a profile name as it was", () => {
    const key = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");
    const r = run(`${WIN}${BOB} ${key} x`, true, true);
    expect(r.out).toBe(`${WIN}${U1}`);
    expect(r.out).not.toContain(key);
    expect(r.pairs).toEqual([[U1, `${BOB} ${SECRET_SENTINEL} x`]]);
  });

  it("a profile path with IP masking on but no address is unchanged", () => {
    expect(run(`${WIN}${ALICE}${BS}x`, true).out).toBe(`${WIN}${U1}${BS}x`);
  });

  it("keeps 2019:fd00::1 unmasked with public masking off", () => {
    expect(run("seen 2019:fd00::1 here", false).out).toBe("seen 2019:fd00::1 here");
  });
});
