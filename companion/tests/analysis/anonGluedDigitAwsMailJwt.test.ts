import { describe, it, expect } from "vitest";
import { redactSecretText } from "../../src/analysis/anonSecrets.js";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3034: an AWS key glued after a digit run (12345 + key) was not found and went to the AI in clear,
// and a JWT glued directly after an e-mail domain (<user>@<internal domain> + eyJ...) was minted inside a
// reversible EMAIL token. Every secret-shaped value is assembled at runtime, so no secret-shaped
// literal sits in the repo (like previewDiff.test.ts).
const join = (...parts: string[]) => parts.join("");
const AT = String.fromCharCode(0x40);
const AWS = join("AK", "IA", "QZ7WXCVBNMLKJHGF");
const ACCA_KEY = join("AC", "CA", "QZ7WXCVBNMLKJHGF");
const JWT = join("ey", "J", "abcdefgh.ijklmnop.qrst");
const INTERNAL = join("contoso", ".local");
const hexRun = (n: number, seed: number) =>
  Array.from({ length: n }, (_, i) => "0123456789ABCDEF"[(i * 7 + seed) % 16]).join("");
const digits = (n: number) => Array.from({ length: n }, (_, i) => String((i * 3 + 1) % 10)).join("");

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

describe("an AWS key glued after a digit run (#3034)", () => {
  it.each([
    [`id 12345${AWS}`, `id 12345${SEC}`],
    [`9${AWS}`, `9${SEC}`],
    [`key=007${AWS} end`, `key=007${SEC} end`],
    [`x9${AWS}`, `x9${SEC}`],
    [`at 20240101${ACCA_KEY}.`, `at 20240101${SEC}.`],
  ])("redacts %s one way", (text, want) => {
    expect(redactSecretText(text)).toBe(want);
  });

  it.each([true, false])("sends no part of the key out, maskPublicIps=%s", (mask) => {
    for (const text of [`id 12345${AWS} ok`, `logon 2024${AWS}`, `C:\\Users\\bob\\9${AWS}.txt`]) {
      const r = run(text, mask);
      expect(r.out).not.toContain(AWS.slice(4, 12));
      expect(r.held.some((v) => v.includes(AWS.slice(4, 12)))).toBe(false);
    }
  });

  it("leaves upper-case hex hashes with ACCA after a digit run readable", () => {
    for (const len of [32, 40, 64]) {
      const at = len - 20;
      const hash = join(digits(at), "ACCA", hexRun(16, len));
      for (const text of [hash, `md5=${hash}x`, `${hash}_x`, `Hashes: SHA256=${hash}`, `file_${hash}.bin`])
        expect(redactSecretText(text)).toBe(text);
    }
    const guid = join(digits(12), "ACCA", hexRun(16, 3));
    expect(redactSecretText(`{${guid}}`)).toBe(`{${guid}}`);
  });

  it("still needs the digit run to start at a seam", () => {
    for (const text of [`SRV9${AWS}`, `HOST12${AWS}`, `ABC${digits(4)}${AWS}`])
      expect(redactSecretText(text)).toBe(text);
  });

  it("stays fast on a long run of digits", () => {
    const text = digits(60_000) + "AKIA";
    const t = performance.now();
    expect(redactSecretText(text)).toBe(text);
    expect(performance.now() - t).toBeLessThan(1000);
  });
});

describe.each([true, false])("a JWT glued after an e-mail domain, maskPublicIps=%s (#3034)", (mask) => {
  it.each([
    ["an internal address", `user bob${AT}${INTERNAL}${JWT}`],
    ["a UPN in a subdomain", `jsmith${AT}corp.${INTERNAL}${JWT} end`],
    ["a public address", `from bob${AT}${join("gmail", ".com")}${JWT}`],
  ])("sends %s and the token one way", (_n, text) => {
    const r = run(text, mask);
    expect(r.out).toContain(SEC);
    expect(r.out).not.toContain("bob");
    expect(r.out).not.toContain("jsmith");
    expect(r.out).not.toContain(JWT.slice(3, 9));
    expect(r.out).not.toContain("qrst");
    expect(r.held.some((v) => v.includes(JWT.slice(3, 9)))).toBe(false);
  });
});

describe("a host or file name that only looks like a glued JWT (#3034)", () => {
  it("stays readable", () => {
    for (const text of [
      `mail x${AT}turkeyJerky01.${INTERNAL}`,
      `mail x${AT}mail.turkeyJerky01.${INTERNAL}`,
      `x${AT}corp.keyJournal.backup2023.gzipx`,
      `x${AT}corp.hockeyJersey2023.${INTERNAL}`,
      `turkeyJerky01.${INTERNAL}`,
      "keyJournal.backup2023.gzipx",
      `C:\\x\\monkeyJump_ab12cd.logfile_2023.archive`,
    ])
      expect(redactSecretText(text)).toBe(text);
  });

  it("stays fast on a long dotted address", () => {
    const text = `${"a".repeat(30)}${AT}${"b.".repeat(30_000)}eyJ`;
    const t = performance.now();
    redactSecretText(text);
    expect(performance.now() - t).toBeLessThan(1000);
  });
});
