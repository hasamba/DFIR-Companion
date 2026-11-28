import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type CustomEntity,
  type KnownEntities,
} from "../../src/analysis/anonymize.js";

// #3020: a custom or saved value is minted before the account pass, so on a later call `CORP\bob`
// reached it as `ANON_DOMAIN_1\bob` and the user half went out in clear. The account pass now reads
// an account whose qualifier holds a minted token and applies the rules a fresh call applies.

const LOCAL = ["corp", "local"].join("."); // built at runtime: a synthetic internal domain
const KNOWN: KnownEntities = { hosts: [], accounts: [], internalDomains: [LOCAL] };
function policy(): AnonPolicy {
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
      CARD: false,
      PHONE: false,
      NATID: false,
    },
  };
}
const at = (user: string, domain: string) => [user, domain].join("@"); // built at runtime
const custom = (value: string, category: CustomEntity["category"]) => [{ value, category }];

function run(text: string, known: KnownEntities) {
  const a = createAnonymizer(policy(), known);
  const out = a.apply(text);
  return { out, back: a.restore(out) };
}

describe("an account whose qualifier a custom or saved value masked (#3020)", () => {
  it("masks the user half after an OCR-saved qualifier, in any case", () => {
    const first = createAnonymizer(policy(), KNOWN);
    first.apply("seen CORP\\alice");
    expect(first.discoveries()).toContainEqual({ value: "CORP", category: "DOMAIN" });
    const text = "later CORP\\bob; corp\\carol";
    const { out, back } = run(text, { ...KNOWN, custom: first.discoveries() });
    expect(out).not.toMatch(/bob|carol/);
    expect(back.toLowerCase()).toBe(text.toLowerCase());
  });

  it.each([
    ["an analyst DOMAIN", "CORP", "DOMAIN", "by CORP\\bob ok"],
    ["a HOST", "WS01", "HOST", "by WS01\\bob ok"],
    ["an OTHER value", "CORP", "OTHER", "by CORP\\bob ok"],
    ["a dotted DOMAIN", LOCAL, "DOMAIN", `by ${LOCAL}\\bob ok`],
    ["part of the qualifier", "CORP", "DOMAIN", "by x-CORP\\bob ok"],
  ] as const)("masks the user half behind %s", (_label, value, category, text) => {
    const { out, back } = run(text, { ...KNOWN, custom: custom(value, category) });
    expect(out).not.toMatch(/bob/);
    expect(back).toBe(text);
  });

  it.each([
    ["the whole internal domain", LOCAL, at("bob", LOCAL)],
    ["part of the internal domain", "corp", at("bob", LOCAL)],
    ["an external domain", "evil.example", at("bob", "evil.example")],
  ])("masks the user of an address behind %s", (_label, value, address) => {
    const text = `mail ${address} ok`;
    const { out, back } = run(text, { ...KNOWN, custom: custom(value, "DOMAIN") });
    expect(out).not.toMatch(/bob/);
    expect(back).toBe(text);
  });

  it("reads a long user half whole, so no tail of it goes out in clear", () => {
    const text = `by CORP\\jdoe-alpha.${LOCAL} ok`;
    const { out, back } = run(text, { ...KNOWN, custom: custom("CORP", "DOMAIN") });
    expect(out).not.toMatch(/jdoe/);
    expect(back.toLowerCase()).toBe(text.toLowerCase()); // the custom value restores in its own case
  });

  it("reads a user half glued to a letter outside A-Z on with it", () => {
    const text = "by CORP\\x-12-élan ok";
    const { out, back } = run(text, { ...KNOWN, custom: custom("CORP", "DOMAIN") });
    expect(out).toBe("by ANON_DOMAIN_1\\ANON_USER_1 ok");
    expect(back).toBe(text);
  });

  it("stops a long user half before a SID, which keeps its own token", () => {
    const text = "by CORP\\jdoe-S-1-5-21-1-2-3-4 ok";
    const { out } = run(text, { ...KNOWN, custom: custom("CORP", "DOMAIN") });
    expect(out).toBe("by ANON_DOMAIN_1\\ANON_USER_1-ANON_REG_1 ok");
  });

  it("masks a file-name user as one whole value, as a fresh call does", () => {
    const text = "ran CORP\\evil.exe";
    const { out } = run(text, { ...KNOWN, custom: custom("CORP", "DOMAIN") });
    expect(out).toBe("ran ANON_USER_1");
  });

  it("keeps a suppressed account as it is", () => {
    const { out } = run("by CORP\\bob ok", {
      ...KNOWN,
      custom: custom("CORP", "DOMAIN"),
      suppressed: ["CORP\\bob"],
    });
    expect(out).toBe("by ANON_DOMAIN_1\\bob ok");
  });

  it("starts the user of an address at a word, as a fresh call does", () => {
    const text = `by zoë-${at("jdoe", LOCAL)} ok`;
    const { out, back } = run(text, { ...KNOWN, usernames: ["zoë"] });
    expect(out).toBe("by ANON_USER_2-ANON_USER_1@ANON_DOMAIN_1 ok");
    expect(back).toBe(text);
  });

  it.each([
    ["the qualifier", "by x-CORP\\bob", "x-CORP", true],
    ["the account", "by x-CORP\\bob", "x-CORP\\bob", true],
    ["the domain, email off", `mail ${at("bob", LOCAL)}`, LOCAL, false],
    ["the address", `mail ${at("bob", LOCAL)}`, at("bob", LOCAL), true],
  ])("never sends a custom value out in clear when %s is suppressed", (_l, text, veto, email) => {
    const known = { ...KNOWN, custom: custom("corp", "DOMAIN"), suppressed: [veto] };
    const p = policy();
    const a = createAnonymizer({ ...p, categories: { ...p.categories, EMAIL: email } }, known);
    expect(a.apply(text)).not.toMatch(/corp/i);
  });

  it("masks a dotted user behind a saved qualifier (the #3028 sweep row)", () => {
    const known = { ...KNOWN, hosts: ["srv01"] };
    const first = createAnonymizer(policy(), known);
    first.apply("logon CORP\\jdoe");
    const text = "CORP\\jsmith.adm\nsrv01\nTools\\jsmith.adm.exe";
    const { out, back } = run(text, { ...known, custom: first.discoveries() });
    expect(out).not.toMatch(/jsmith|adm/);
    expect(back).toBe(text);
  });

  it("reads an account whose qualifier is the last word of a saved profile name", () => {
    const text = "C:\\Users\\ab dave\\xC:\\Users\\x";
    const fresh = run(text, KNOWN).out;
    expect(fresh).not.toMatch(/xC/);
    const first = createAnonymizer(policy(), KNOWN);
    first.apply(text);
    const { out, back } = run(text, { ...KNOWN, custom: first.discoveries() });
    expect(out).not.toMatch(/dave|xC/);
    expect(back).toBe(text);
  });

  it("reads the user of an address glued after a masked one", () => {
    const text = `by ${at("zz", "evil.example")}-${at("zz", LOCAL)} ok`;
    const { out, back } = run(text, { ...KNOWN, custom: custom(at("zz", "evil.example"), "EMAIL") });
    expect(out).not.toMatch(/zz/);
    expect(back).toBe(text);
  });

  it("leaves the server of a UNC path alone", () => {
    const known = { ...KNOWN, custom: custom("WS01", "HOST") };
    expect(run("open \\\\WS01\\share", known).out).toBe("open \\\\ANON_HOST_1\\share");
  });
});
