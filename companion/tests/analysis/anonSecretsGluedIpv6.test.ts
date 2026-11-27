import { describe, it, expect } from "vitest";
import { expectLinearScan } from "../helpers/growth.js";
import { redactSecretText, SECRET_PLACEHOLDER as PH } from "../../src/analysis/anonSecrets.js";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3016 — a vendor token or a bare Bearer value glued directly to an IPv6 address took the hex head
// of the address (`fd00` of `fd00::2`), so the rest (`::2`) went to the AI in clear, or was tokenized
// as the wrong address. The address now goes into the same one-way placeholder as the token. Every
// fixture secret is built at runtime.
const join = (...parts: string[]) => parts.join("");
const rep = (s: string, n: number) => s.repeat(Math.ceil(n / s.length)).slice(0, n);

const JWT = join("ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0In0", ".", "Sf1KxwRJSMeKKF2QT4fwpM");
const SLACK = join("xo", "xb-", "1234567890-abcdefghij");
const GHP = join("gh", "p_", rep("a1B2", 36));
const STRIPE = join("sk", "_live_", rep("Lm12No34", 24));
const NPM = join("np", "m_", rep("N1p2", 36));
const BEARER = join("abc.def-", "123e");

describe("redactSecretText — a token glued to an IPv6 address hides the whole address (#3016)", () => {
  const addresses = ["fd00::2", "fe80::1", "2001:db8::1", "fd00::ffff:10.0.0.5", "fe80::1:2:3"];
  const tokens: [string, string][] = [
    ["JWT", JWT],
    ["Slack", SLACK],
    ["GitHub", GHP],
    ["Stripe", STRIPE],
    ["npm", NPM],
  ];
  for (const [name, token] of tokens) {
    it.each(addresses)(`${name} token, then %s`, (address) => {
      const out = redactSecretText(`src=${token}${address} next`);
      expect(out).toBe(`src=${PH} next`);
    });
  }

  it.each(addresses)("a bare Bearer value, then %s", (address) => {
    const out = redactSecretText(`Authorization: Bearer ${BEARER}${address} next`);
    expect(out).not.toContain(BEARER);
    expect(out).not.toMatch(/::|db8|ffff/);
    expect(out).toContain(PH);
  });

  it("takes a fifth dotted number, and leaves a sentence-ending dot", () => {
    expect(redactSecretText(`${SLACK}fd00::ffff:10.0.0.5.7 x`)).toBe(`${PH} x`);
    expect(redactSecretText(`${SLACK}fd00::2. Next`)).toBe(`${PH}. Next`);
  });

  it("a bare Bearer value stays readable when it has no digit or symbol, even before ::", () => {
    expect(redactSecretText("bearer authentication::")).toBe("bearer authentication::");
  });
});

describe("redactSecretText — colon shapes after a token stay as they were (#3016)", () => {
  it.each([":12:34:56", ":aa:bb:cc:dd:ee", "::Method()", ":443", ":443/path", " 10:20:30"])(
    "JWT, then %s",
    (tail) => {
      expect(redactSecretText(`${JWT}${tail}`)).toBe(`${PH}${tail}`);
    },
  );

  it.each([
    "aa:bb:cc:dd:ee:ff",
    "ab12::Method",
    "deadbeef:12:34",
    "C:\\x\\cafe::$DATA",
    "12:34:56.789",
    "fe80::1%eth0",
  ])("keeps %s", (row) => {
    expect(redactSecretText(row)).toBe(row);
  });
});

describe("anonymizer — a token glued to an IPv6 address (#3016)", () => {
  const cats = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true };
  it.each([true, false])("no part of the address goes out in clear (public masking %s)", (mask) => {
    const anon = createAnonymizer(
      { enabled: true, redactSecrets: true, maskPublicIps: mask, categories: cats } as AnonPolicy,
      { hosts: [], accounts: [], internalDomains: [] },
    );
    for (const row of [`${JWT}fd00::2`, `${SLACK}fe80::1`, `Bearer ${BEARER}2001:db8::1`]) {
      const out = anon.apply(row);
      expect(out).not.toMatch(/::|db8|ANON_IP/);
      expect(out).toContain(PH);
    }
  });
});

describe("anonymizer — the tail never stops part-way through what the address pass masks (#3016)", () => {
  const cats = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true };
  const anon = () =>
    createAnonymizer(
      { enabled: true, redactSecrets: true, maskPublicIps: true, categories: cats } as AnonPolicy,
      {
        hosts: [],
        accounts: [],
        internalDomains: ["example.test"],
      },
    );
  it.each([
    [`${SLACK}fd00::ffff:10.0.0.5fd00::2`, "10.0.0.5"],
    [join(SLACK, "fe80::15", "@", "example.test"), "example.test"],
    [`Bearer ${BEARER}.0.0.52019:fd00::1192.168.1.5`, "fd00"],
  ])("%s keeps %s masked", (row, value) => {
    expect(anon().apply(row)).not.toContain(value);
  });
});

describe("anonymizer — an address glued after a redacted token is not split (#3005)", () => {
  // Since #3005 redacts a token glued to an address, the address pass saw only what the token left
  // (`::ffff:10.0.0.5` plus glued digits) and split it, so part of an address master masked whole
  // went out in clear.
  const cats = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true, CMD: true };
  const blob = "SQBFAFgAIAAoAE4AZQB3AC0ATwBi";
  const anon = (mask: boolean) =>
    createAnonymizer(
      { enabled: true, redactSecrets: true, maskPublicIps: mask, categories: cats } as AnonPolicy,
      {
        hosts: [],
        accounts: [],
        internalDomains: [],
      },
    );
  const glued = ["::5", "192.168.1.5", "23456789", "0::2", "fd00::2", ""];
  for (const mask of [true, false]) {
    it.each(glued)(`a token, fd00::ffff:10.0.0.5, then %s (public masking ${mask})`, (after) => {
      const out = anon(mask).apply(`x ${SLACK}fd00::ffff:10.0.0.5${after} y`);
      expect(out).not.toMatch(/ffff|10\.0\.0|::/);
      expect(out).not.toContain(SLACK);
      expect(out).toContain(PH);
    });
  }

  it("the token right after the address is still found", () => {
    const out = anon(true).apply(`Bearer ${BEARER}2001:db8::1${JWT} x`);
    expect(out).not.toContain(JWT.slice(-12));
    expect(out).not.toContain("db8");
  });

  it("an encoded command right after the address is still masked", () => {
    const out = anon(true).apply(`Bearer ${BEARER}2001:db8::15FromBase64String('${blob}==')`);
    expect(out).not.toContain(blob);
    expect(out).toMatch(/ANON_CMD_\d+/);
  });
});

describe("redactSecretText — the glued-address tail scans in linear time (#3016)", () => {
  it.each([
    ["token then colon groups", (n: number) => `${SLACK}a` + ":ab".repeat(n)],
    ["token then :: runs", (n: number) => `${SLACK}a` + "::a".repeat(n)],
    ["tokens glued to colons", (n: number) => `${SLACK}a::`.repeat(n)],
    ["Bearer then colon groups", (n: number) => `Bearer ${BEARER}` + ":1".repeat(n)],
    ["token then a long hex-letter word", (n: number) => `${SLACK}a::a` + "b".repeat(n)],
    ["tokens before hex-letter runs", (n: number) => `${SLACK}a::a${"b".repeat(80)} `.repeat(n)],
  ])("%s", (name, bait) => {
    expectLinearScan(name, (n) => redactSecretText(bait(n)), 2000);
  });
});
