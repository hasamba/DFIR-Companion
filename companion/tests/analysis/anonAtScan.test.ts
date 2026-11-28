import { describe, it, expect } from "vitest";
import { expectLinearScan } from "../helpers/growth.js";
import { atAnchored } from "../../src/analysis/anonAtScan.js";
import { UPN_ACCT } from "../../src/analysis/anonUsernames.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3055: the account and e-mail patterns scanned every run of local-part characters once per word
// boundary in it, so a long run took quadratic time on every masked call.
const EMAIL_LIKE =
  /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+(?:\.[A-Za-z]{2,}|\.xn--[A-Za-z0-9-]+)\b/g;
const AT = "@";
const DOM = ["corp", "local"].join(".");

let seed = 3055;
const rnd = () => {
  seed = (seed * 1103515245 + 12345) & 0x7fffffff;
  return seed / 0x7fffffff;
};
const ALPHABET = ["a", "b", "Z", "0", "7", ".", "-", "_", "%", "+", AT, AT, " ", "\\", "x", "n", "é", ":"];
const randomText = (len: number) =>
  Array.from({ length: len }, () => ALPHABET[Math.floor(rnd() * ALPHABET.length)]).join("");

describe("atAnchored — the same matches as the regex, read in linear time (#3055)", () => {
  it("returns exactly what String.replace with the regex returns", () => {
    const fn = (m: string, at: number) => `<${at}:${m}>`;
    for (const [re, min] of [
      [UPN_ACCT, 2],
      [EMAIL_LIKE, 1],
    ] as const) {
      for (let i = 0; i < 3000; i++) {
        const t = randomText(1 + Math.floor(rnd() * 40));
        expect(t.replace(atAnchored(re, min), fn), t).toBe(t.replace(re, fn));
      }
    }
  });

  it("keeps the leftmost start the regex takes", () => {
    const fn = (m: string) => `[${m}]`;
    for (const t of [`_.bob${AT}x.com`, `..bob${AT}x.com`, `a_bob${AT}x.com`, `a${AT}b.com.x${AT}y.com`]) {
      expect(t.replace(atAnchored(EMAIL_LIKE, 1), fn)).toBe(t.replace(EMAIL_LIKE, fn));
      expect(t.replace(atAnchored(UPN_ACCT, 2), fn)).toBe(t.replace(UPN_ACCT, fn));
    }
  });
});

const ALL: AnonPolicy["categories"] = {
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
};

describe("apply() stays linear on long local-part runs (#3055)", () => {
  const anonymizer = () =>
    createAnonymizer(
      { enabled: true, redactSecrets: true, maskPublicIps: true, categories: ALL },
      { hosts: [], accounts: [], internalDomains: [DOM], usernames: ["jdoe"] },
    );
  const shapes: Array<[string, (n: number) => string]> = [
    ["an e-mail domain of sk- runs", (n) => `x${AT}${"sk-".repeat(n)}`],
    ["an e-mail domain of dotted labels", (n) => `x${AT}${"ab.".repeat(n)}com`],
    ["a URL-encoded body with no @", (n) => "%41".repeat(n)],
    ["a dashed slug with no @", (n) => "a-".repeat(n)],
  ];
  for (const [label, bait] of shapes) {
    it(label, () => {
      const a = anonymizer();
      expectLinearScan(`anonymizer ${label}`, (n) => a.apply(bait(n)), 1000);
    });
  }
});
