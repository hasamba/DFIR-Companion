import { describe, it, expect } from "vitest";
import { VENDOR_SECRETS } from "../../src/analysis/anonSecrets.js";
import { GLUED_VENDOR_SECRETS, holdsGluedSecret } from "../../src/analysis/anonGluedSecret.js";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3003: a secret glued into a profile-path name was missed by the edge-guarded secret shapes, and
// the whole name became a reversible USER token: restore() handed the secret back, and the OCR path
// saved it as a discovery. Such a name now goes one way. Every path prefix and secret-shaped value is
// assembled at runtime, so no secret-shaped literal sits in the repo (like previewDiff.test.ts).
const join = (...parts: string[]) => parts.join("");
const rep = (s: string, n: number) => s.repeat(Math.ceil(n / s.length)).slice(0, n);
const BS = String.fromCharCode(0x5c);
const WIN = ["C:", "Users", ""].join(BS);
const HOME = ["", "home", ""].join("/");
const U = (n: number) => ["ANON", "USER", String(n)].join("_");

const AWS = join("AK", "IA", "QZ7WXCVBNMLKJHGF");
const SK = join("s", "k-", "Ab12Cd34Ef56Gh78Ij90Kl12");
const JWT = join("ey", "J", "abcdefghij.klmnopqrst.uvwxyz12");
const PASSWORD = join("pass", "word=", "Sup3rS3cretValue99");
const CORE = (s: string) => s.slice(6, 14);

// One sample per VENDOR_SECRETS entry, in its order.
const HEADER = join("ey", "J", "hbGciOiJIUzI1NiJ9");
const PAYLOAD = join("ey", "JzdWIiOiIxMjM0In0");
const SAMPLES = [
  AWS,
  join("9", AWS), // ... glued after a digit run (#3034)
  join("gh", "s_", "123456_", HEADER, ".", PAYLOAD, ".", "Sf1KxwRJSMeK"),
  JWT,
  join(HEADER, ".", PAYLOAD, ".", "Sf1KxwRJSMeK"),
  join(String.fromCharCode(0x40), "corp", ".local", JWT), // ... glued after an e-mail domain (#3034)
  join("github", "_pat_", rep("A1b2C3d4", 30)),
  join("gh", "p_", rep("a1B2", 24)),
  join("gh", "p_", rep("a1B2", 36)),
  join("xo", "xb-", "1234567890-abcdefghij"),
  join("xa", "pp-", "1-", "A0123BCDE-", rep("0123456789", 24)),
  join("AI", "za", rep("Qw", 35)),
  join("sk", "_test_", rep("Lm12No34", 24)),
  join("sk", "_live_", rep("Lm12No34", 24)),
  join("sk-", "proj-", rep("Ab12Cd34", 24)),
  join("sk-", "svcacct-", rep("Ab12Cd34", 24)),
  join("sk-", "ant-", "api03-", rep("Ab12Cd34", 24)),
  join("sk-", rep("Ab12Cd34", 12), "T3Blbk", "FJ", rep("Kl12Mn34", 12)),
  SK,
  join(BS, SK), // ... glued after a name in an account (#3029)
  join("S", "G.", rep("Ab12Cd34", 12), ".", rep("Mn34Op56", 12)),
  join("S", "G.", rep("Ab12Cd34", 22), ".", rep("Mn34Op56", 43)),
  join("np", "m_", rep("N1p2", 40)),
  join("np", "m_", rep("N1p2", 36)),
  join("twilio ", "AC", rep("0123456789ABCDEF", 32)),
];

function policy(redactSecrets = true, maskPublicIps = true): AnonPolicy {
  const on = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets,
    maskPublicIps,
    categories: { ...on, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
const known = (extra: Partial<KnownEntities> = {}): KnownEntities => ({
  hosts: [],
  accounts: [],
  internalDomains: [],
  ...extra,
});
function run(text: string, opts: { secrets?: boolean; mask?: boolean; usernames?: string[] } = {}) {
  const a = createAnonymizer(policy(opts.secrets ?? true, opts.mask ?? true), known(opts));
  const out = a.apply(text);
  const held = [...a.pairs().map((p) => p.value), ...a.discoveries().map((d) => d.value)];
  return { a, out, back: a.restore(out), held };
}

describe("the edge-free vendor shapes", () => {
  it("are derived one for one from VENDOR_SECRETS with no edge guard left", () => {
    expect(GLUED_VENDOR_SECRETS).toHaveLength(VENDOR_SECRETS.length);
    for (const re of GLUED_VENDOR_SECRETS) {
      expect(re.source).not.toMatch(/\\b|\(\?<?!\[[^\]]*\](?:\{[\d,]*\})?\)/);
      expect(re.flags).not.toContain("g");
    }
  });

  it("each match its vendor sample glued to text on both sides", () => {
    expect(SAMPLES).toHaveLength(GLUED_VENDOR_SECRETS.length);
    GLUED_VENDOR_SECRETS.forEach((re, i) => {
      const s = SAMPLES[i];
      const glued = s.startsWith("twilio ") ? s.replace(" ", " bob") + "x" : `bob${s}x`;
      expect(re.test(glued), re.source).toBe(true);
    });
  });

  it("keep what tells a key from a hash or a word", () => {
    expect(holdsGluedSecret(join("bob", "AC", rep("0123456789ABCDEF", 32), "x"))).toBe(false); // no Twilio label
    for (const name of [
      "jsmith",
      "sk-admin",
      "desk-operator01",
      "MSSQL$SQLEXPRESS",
      "npm_builder",
      "bob_token",
    ])
      expect(holdsGluedSecret(name)).toBe(false);
  });

  it("find a key=value straight after the path separator", () => {
    expect(holdsGluedSecret(PASSWORD)).toBe(true);
    expect(holdsGluedSecret(`bob${PASSWORD}`)).toBe(true);
  });
});

describe.each([true, false])("a secret glued into a profile name, maskPublicIps=%s (#3003)", (mask) => {
  it.each([
    ["a password= pair after the name", `${WIN}bob${PASSWORD}`],
    ["a password= pair as the name", `${WIN}${PASSWORD}`],
    ["an OpenAI key after a built-in name", `${HOME}Public${SK}`],
    ["a JWT after the name", `${HOME}bob_${JWT}`],
    ["a JWT and one more letter", `${HOME}bob${JWT}x`],
    ["an AWS key and one more letter", `${WIN}bob${AWS}x`],
  ])("never keeps %s in a reversible token", (_n, path) => {
    const r = run(`${path}${BS}AppData x`, { mask });
    expect(r.out).toContain(SEC);
    for (const s of [AWS, SK, JWT, PASSWORD]) {
      expect(r.out).not.toContain(CORE(s));
      expect(r.held.some((v) => v.includes(CORE(s)))).toBe(false);
    }
  });

  it("shows the name as [REDACTED_SECRET] and restores the placeholder", () => {
    const r = run(`${WIN}bob${SK}${BS}AppData`, { mask });
    expect(r.out).toBe(`${WIN}${SEC}${BS}AppData`);
    expect(r.back).toBe(`${WIN}${SEC}${BS}AppData`);
    expect(r.held).toEqual([]);
  });

  it("sends a bare repeat of the name one way, in any letter case and on a later call", () => {
    const name = `bob${SK}`;
    const r = run(`${WIN}${name}${BS}x then ${name} and ${name.toUpperCase()}`, { mask });
    expect(r.out).toBe(`${WIN}${SEC}${BS}x then ${SEC} and ${SEC}`);
    expect(r.a.apply(`later ${name.toLowerCase()} again`)).toBe(`later ${SEC} again`);
    expect(r.held).toEqual([]);
  });

  it("sends a username seed that holds a glued secret one way", () => {
    const name = `bob${SK}`;
    const r = run(`the ${name} account`, { mask, usernames: [name] });
    expect(r.out).toBe(`the ${SEC} account`);
    expect(r.held).toEqual([]);
  });

  it("saves no OCR word that holds the secret", () => {
    for (const word of [`${WIN}bob${SK}`, `${HOME}bob${PASSWORD}x`, `${WIN}bob_${JWT}end`]) {
      const r = run(word, { mask });
      expect(r.a.discoveries()).toEqual([]);
      expect(r.held.some((v) => [SK, PASSWORD, JWT].some((s) => v.includes(CORE(s))))).toBe(false);
    }
  });

  it("keeps the #3002 split around a secret the main pass found", () => {
    const r = run(`${WIN}bob ${AWS} zqmarker end`, { mask });
    expect(r.out).toBe(`${WIN}${U(1)} ${SEC} ${U(2)}`);
  });

  it("leaves names with no secret, and secret redaction turned off, as they were", () => {
    expect(run(`${WIN}jsmith${BS}x and jsmith`, { mask }).out).toBe(`${WIN}${U(1)}${BS}x and ${U(1)}`);
    expect(run(`${HOME}desk-operator01${BS}x`, { mask }).out).toBe(`${HOME}${U(1)}${BS}x`);
    const off = run(`${WIN}bob${SK}${BS}x`, { mask, secrets: false });
    expect(off.out).toBe(`${WIN}${U(1)}${BS}x`);
  });
});
