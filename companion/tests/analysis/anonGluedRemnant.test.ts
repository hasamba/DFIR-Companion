import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  SECRET_PLACEHOLDER as SEC,
  type AnonPolicy,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3028: since #3005 a vendor key glued inside a word is redacted, and the account, e-mail, path and
// bare-name passes then saw only the text left around the placeholder, which went to the AI in clear.
// The rest of that word now goes one way with the key. Every secret, path prefix, e-mail and address
// is assembled at runtime, so no secret-shaped literal sits in the repo (like previewDiff.test.ts).
const join = (...parts: string[]) => parts.join("");
const BS = String.fromCharCode(0x5c);
const AT = String.fromCharCode(0x40);
const AWS = join("AK", "IA", "QZ7WXCVBNMLKJHGF");
const GHP = join("gh", "p_", "a1B2".repeat(9));
const SK = join("s", "k-", "Ab12Cd34Ef56Gh78Ij90Kl12");
const KEYS = [AWS, GHP, SK];
const CORE = (s: string) => s.slice(6, 14);
const INTERNAL = join("contoso", ".local");
const MAIL = join("mail", ".example", ".org");
const WIN = ["C:", "Users", ""].join(BS);
const TOKEN = /ANON_[A-Z]+_\d+/;

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
  return { a, out, held };
}

function expectNoKey(r: ReturnType<typeof run>) {
  for (const k of KEYS) {
    expect(r.out).not.toContain(CORE(k));
    expect(r.held.some((v) => v.includes(CORE(k)))).toBe(false);
  }
}

describe.each([true, false])("text glued to a redacted key, maskPublicIps=%s (#3028)", (mask) => {
  it.each([
    ["an admin name before a key, in an internal e-mail", `jsmith.adm${AWS}${AT}${INTERNAL}`],
    ["a name before a key, in an external e-mail", `bob${GHP}${AT}${MAIL}`],
    ["a name before a key, after a mail header", `From:jsmith.adm${AWS}${AT}corp.${INTERNAL}`],
    ["a name before a key, in a mailto link", `mailto:bob${GHP}${AT}${MAIL}`],
    ["a built-in profile name before a key", `Public${SK}${AT}${MAIL}`],
    ["a key before a name, in a sub-domain e-mail", `${AWS}bob${AT}corp.${INTERNAL}`],
  ])("hides %s whole", (_n, email) => {
    const r = run(`logon ${email} ok`, mask);
    const label = /^(?:From|mailto):/.exec(email)?.[0] ?? ""; // a label before the address stays
    expect(r.out).toBe(`logon ${label}${SEC} ok`);
    expectNoKey(r);
  });

  it("hides a tool folder and the file name glued to a key", () => {
    const r = run(`ran Tools${BS}${SK}svc_backup.exe now`, mask);
    expect(r.out).toBe(`ran ${SEC} now`);
    expectNoKey(r);
  });

  it("hides the DOMAIN of an account whose name holds a key, and a later repeat in any case", () => {
    const name = `bob${AWS}`;
    const r = run(`CORP${BS}${name} then ${name.toLowerCase()} and ${name}`, mask);
    expect(r.out).toBe(`${SEC} then ${SEC} and ${SEC}`);
    expect(r.a.apply(`later ${name.toLowerCase()}`)).toBe(`later ${SEC}`);
    expectNoKey(r);
  });

  it("hides a profile name glued to a key and keeps the rest of the path", () => {
    const r = run(`${WIN}${AWS}bob${BS}AppData x`, mask);
    expect(r.out).toBe(`${WIN}${SEC}${BS}AppData x`);
    expectNoKey(r);
  });

  it("takes the user after a glued tail that reads as a DOMAIN", () => {
    const r = run(`${WIN}${GHP}MSSQL$SQLEXPRESS${BS}AppData`, mask);
    expect(r.out).toBe(`${WIN}${SEC}`);
    expectNoKey(r);
  });

  it("never takes part of an address glued to the key", () => {
    const mapped = join("::ffff:", "10.0.0.5");
    const v6 = join("2001:db8", "::5");
    const a = run(`${mapped}${GHP} end`, mask).out;
    expect(a).toMatch(new RegExp(`^${TOKEN.source}\\[REDACTED_SECRET\\] end$`));
    const b = run(`${AWS}${AT}${v6} end`, mask).out;
    // A public address stays in clear with public masking off, as it did before.
    if (mask) expect(b).toMatch(new RegExp(`^\\[REDACTED_SECRET\\]${AT}${TOKEN.source} end$`));
    else expect(b).toBe(`${SEC}${AT}${v6} end`);
  });

  it("keeps the host of URL userinfo, and hides a name glued to the key with its host", () => {
    const pw = run(`https://bob:${GHP}${AT}git.${INTERNAL}/repo`, mask).out;
    expect(pw).toMatch(new RegExp(`^https://bob:\\[REDACTED_SECRET\\]${AT}git\\.${TOKEN.source}/repo$`));
    const bare = run(`https://${GHP}${AT}evil.example.org/x`, mask).out;
    expect(bare).toBe(`https://${SEC}${AT}evil.example.org/x`);
    const glued = run(`see https://bob${GHP}${AT}${MAIL}/a`, mask).out;
    expect(glued).toBe(`see https://${SEC}/a`);
  });

  it("hides the whole e-mail when the key is glued after its domain", () => {
    for (const glue of ["", "-", "."]) {
      const r = run(`logon jdoe${AT}${INTERNAL}${glue}${AWS} ok`, mask);
      expect(r.out).toBe(`logon ${SEC} ok`);
      expectNoKey(r);
    }
  });

  it("never takes the tail of a folder name too long to be a DOMAIN", () => {
    expect(run(`WindowsPowerShell${BS}${AWS} x`, mask).out).toBe(`WindowsPowerShell${BS}${SEC} x`);
    expect(run(`CONTOSO-LAB-001${BS}${AWS} x`, mask).out).toBe(`${SEC} x`);
  });

  it("never cuts a card number, an encoded command or a custom value glued to the key", () => {
    const card = ["4111", "1111", "1111", "1111"].join(" ");
    expect(run(`card ${card}${GHP} x`, mask).out).toMatch(
      new RegExp(`^card ${TOKEN.source}\\[REDACTED_SECRET\\] x$`),
    );
    const blob = join("SQBFAFgAIAAo", "/", "AE4AZQB3AC0ATwBi");
    expect(run(`run -enc ${blob}${AWS} x`, mask).out).toMatch(new RegExp(`^run -enc ${TOKEN.source}`));
    const a = createAnonymizer(policy(mask), {
      ...known(),
      custom: [{ value: "zq marker", category: "OTHER" }],
    });
    expect(a.apply(`see zq marker-${AWS} x`)).toBe(`see ANON_OTHER_1-${SEC} x`);
  });

  it("leaves a full stop after a key in the sentence", () => {
    expect(run(`token ${AWS}. Next`, mask).out).toBe(`token ${SEC}. Next`);
  });
});
